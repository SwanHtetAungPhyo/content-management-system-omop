package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/consul/api"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type UserClaims struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Groups   []string `json:"groups"`
	Exp      float64  `json:"exp"`
}

var users = []User{
	{1, "John Doe", "john@example.com"},
	{2, "Jane Smith", "jane@example.com"},
}

// JWT Secret - should match your gateway configuration
const jwtSecret = "Z+1mxVqJ9b/lidlCkiLKp10WnTcRAxL2iHJ2aCtFO38="

func main() {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = "localhost:8500"
	client, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Failed to create Consul client: %v", err)
	}

	serviceID := "user-service-1"
	registration := &api.AgentServiceRegistration{
		ID:      serviceID,
		Name:    "user-service",
		Port:    8081,
		Address: getLocalIP(),
		Check: &api.AgentServiceCheck{
			HTTP:     "http://" + getLocalIP() + ":8081/health",
			Interval: "10s",
			Timeout:  "3s",
		},
	}

	err = client.Agent().ServiceRegister(registration)
	if err != nil {
		log.Fatalf("Failed to register service: %v", err)
	}
	log.Println("Service registered with Consul")

	// Deregister service on shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Deregistering service...")
		err := client.Agent().ServiceDeregister(serviceID)
		if err != nil {
			log.Printf("Failed to deregister service: %v", err)
		}
		os.Exit(0)
	}()

	// Initialize Fiber app
	app := fiber.New()

	// Health check endpoint (no auth required)
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Auth middleware for protected routes
	app.Use("/users", authMiddleware)

	// Protected routes
	app.Get("/users", getUsersHandler)
	app.Get("/users/:id", getUserHandler)
	app.Get("/users/me", getCurrentUserHandler)

	app.Get("/debug/claims", func(c *fiber.Ctx) error {
		userClaims := c.Locals("user_claims").(*UserClaims)
		return c.JSON(fiber.Map{
			"claims":  userClaims,
			"headers": getDebugHeaders(c),
		})
	})

	log.Println("User Service starting on :8081")
	log.Fatal(app.Listen(":8081"))
}

func authMiddleware(c *fiber.Ctx) error {
	var userClaims *UserClaims
	var err error

	cookieValue := c.Cookies("X-User-Claims")
	if cookieValue != "" {
		userClaims, err = parseUserClaimsCookie(cookieValue)
		if err != nil {
			log.Printf("Failed to parse user claims cookie: %v", err)
		} else {
			log.Printf("User authenticated via cookie: %s", userClaims.Email)
			c.Locals("user_claims", userClaims)
			c.Locals("auth_method", "cookie")
			return c.Next()
		}
	}

	// Method 2: Try to get from headers set by gateway
	userID := c.Get("X-User-ID")
	userEmail := c.Get("X-User-Email")
	if userID != "" {
		userClaims = &UserClaims{
			UserID: userID,
			Email:  userEmail,
		}
		log.Printf("User authenticated via headers: %s", userEmail)
		c.Locals("user_claims", userClaims)
		c.Locals("auth_method", "headers")
		return c.Next()
	}

	// Method 3: Direct JWT validation (for testing without gateway)
	authHeader := c.Get("Authorization")
	if authHeader != "" {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString != authHeader {
			userClaims, err = validateJWTToken(tokenString)
			if err != nil {
				return c.Status(401).JSON(fiber.Map{
					"error":   "Invalid JWT token",
					"details": err.Error(),
				})
			}
			log.Printf("User authenticated via direct JWT: %s", userClaims.Email)
			c.Locals("user_claims", userClaims)
			c.Locals("auth_method", "jwt")
			return c.Next()
		}
	}

	// No valid authentication found
	return c.Status(401).JSON(fiber.Map{
		"error":   "Authentication required",
		"message": "No valid authentication method found",
	})
}

// Parse user claims from cookie
func parseUserClaimsCookie(cookieValue string) (*UserClaims, error) {
	// Decode from base64
	decodedBytes, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie: %v", err)
	}

	// Parse JSON
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &claimsMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %v", err)
	}

	// Convert to UserClaims struct
	userClaims := &UserClaims{}

	if userID, ok := claimsMap["user_id"].(string); ok {
		userClaims.UserID = userID
	}
	if email, ok := claimsMap["email"].(string); ok {
		userClaims.Email = email
	}
	if username, ok := claimsMap["username"].(string); ok {
		userClaims.Username = username
	}
	if name, ok := claimsMap["name"].(string); ok {
		userClaims.Name = name
	}
	if exp, ok := claimsMap["exp"].(float64); ok {
		userClaims.Exp = exp
	}

	// Handle roles array
	if roles, ok := claimsMap["roles"].([]interface{}); ok {
		for _, role := range roles {
			if roleStr, ok := role.(string); ok {
				userClaims.Roles = append(userClaims.Roles, roleStr)
			}
		}
	}

	// Handle groups array
	if groups, ok := claimsMap["groups"].([]interface{}); ok {
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				userClaims.Groups = append(userClaims.Groups, groupStr)
			}
		}
	}

	return userClaims, nil
}

// Validate JWT token directly (for testing without gateway)
func validateJWTToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userClaims := &UserClaims{}

		if sub, ok := claims["sub"].(string); ok {
			userClaims.UserID = sub
		}
		if email, ok := claims["email"].(string); ok {
			userClaims.Email = email
		}
		if username, ok := claims["username"].(string); ok {
			userClaims.Username = username
		}
		if name, ok := claims["name"].(string); ok {
			userClaims.Name = name
		}
		if exp, ok := claims["exp"].(float64); ok {
			userClaims.Exp = exp
		}

		return userClaims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func getUsersHandler(c *fiber.Ctx) error {
	userClaims := c.Locals("user_claims").(*UserClaims)
	authMethod := c.Locals("auth_method").(string)

	return c.JSON(fiber.Map{
		"users":              users,
		"authenticated_user": userClaims.Email,
		"auth_method":        authMethod,
	})
}

func getUserHandler(c *fiber.Ctx) error {
	userClaims := c.Locals("user_claims").(*UserClaims)
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	for _, user := range users {
		if user.ID == id {
			return c.JSON(fiber.Map{
				"user":         user,
				"requested_by": userClaims.Email,
			})
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"error": "User not found",
	})
}

func getCurrentUserHandler(c *fiber.Ctx) error {
	userClaims := c.Locals("user_claims").(*UserClaims)

	return c.JSON(fiber.Map{
		"current_user": userClaims,
		"message":      "This is your user profile",
	})
}

func getDebugHeaders(c *fiber.Ctx) map[string]string {
	headers := make(map[string]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})
	return headers
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "localhost"
}
