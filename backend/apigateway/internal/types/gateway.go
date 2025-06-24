package types

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/consul/api"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func NewGateway(cfg *Config) *Gateway {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = cfg.ConsulAddr
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatalf("Failed to connect to the consul: %v", err.Error())
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.RedisAddr,
		Password:     "",
		DB:           0,
		PoolSize:     10,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx := context.Background()
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to the redis: %v", err.Error())
	}
	httpClient := &fasthttp.Client{
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		MaxConnsPerHost: 100,
	}
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReadTimeout:           10 * time.Second,
		WriteTimeout:          10 * time.Second,

		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"success": false,
				"message": err.Error(),
			})
		},
	})
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} - ${latency}\n",
	}))
	app.Use(cors.New())

	gw := &Gateway{
		App:        app,
		Consult:    consulClient,
		Redis:      rdb,
		Config:     *cfg,
		HttpClient: httpClient,
		Ctx:        ctx,
	}

	gw.setupRoutes()
	go gw.watchServices()
	return gw
}

func (gw *Gateway) setupRoutes() {
	gw.App.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy", "time": time.Now().Unix()})
	})

	gw.App.Get("/debug/user", func(c *fiber.Ctx) error {
		cookieValue := c.Cookies("X-User-Claims")
		if cookieValue == "" {
			return c.Status(401).JSON(fiber.Map{"error": "No user claims found"})
		}

		userInfo, err := GetUserClaimsFromCookie(cookieValue)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"user_claims": userInfo})
	})

	// Apply routes with individual protection
	for _, route := range gw.Config.Routes {
		gw.App.All(route.Path, gw.createHandler(route))
	}
}

func (gw *Gateway) createHandler(route Route) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Service-level authentication check
		if route.Protected {
			if err := gw.jwtMiddleware()(c); err != nil {
				return err
			}
		}

		// Rate limiting
		if route.RateLimit > 0 {
			limited, err := gw.CheckRateLimit(c.IP(), route.RateLimit)
			if err != nil {
				log.Printf("Rate limit check error: %v", err)
			} else if limited {
				return c.Status(429).JSON(fiber.Map{
					"status": "rate limit exceeded",
					"time":   time.Now().Unix(),
				})
			}
		}

		// Caching for GET requests
		if route.CacheTTL > 0 && c.Method() == "GET" {
			if cached := gw.getCache(gw.cacheKey(c)); cached != nil {
				for k, v := range cached.Headers {
					c.Set(k, v)
				}
				c.Set("X-Cache-Hit", "true")
				return c.Status(cached.StatusCode).Send(cached.Body)
			}
		}

		service := gw.getService(route.Service)
		if service == nil {
			return c.Status(503).JSON(fiber.Map{"status": "service not found", "time": time.Now().Unix()})
		}
		return gw.proxyRequest(c, service, route)
	}
}

func (gw *Gateway) proxyRequest(c *fiber.Ctx, service *ServiceInstance, route Route) error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Fix: Properly handle path stripping and forwarding
	targetPath := c.Path()
	if route.StripPath != "" {
		targetPath = strings.TrimPrefix(targetPath, route.StripPath)
		if !strings.HasPrefix(targetPath, "/") {
			targetPath = "/" + targetPath
		}
	}

	target := fmt.Sprintf("http://%s:%d%s", service.Address, service.Port, targetPath)
	if len(c.Request().URI().QueryString()) > 0 {
		target += "?" + string(c.Request().URI().QueryString())
	}

	req.Header.SetMethod(c.Method())
	req.SetRequestURI(target)

	// Copy headers
	c.Request().Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if k != "Host" && k != "Connection" && k != "Content-Length" {
			req.Header.SetBytesKV(key, value)
		}
	})

	// Copy body for write methods
	if c.Method() == "POST" || c.Method() == "PUT" || c.Method() == "PATCH" {
		req.SetBody(c.Body())
	}

	err := gw.HttpClient.Do(req, resp)
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"status": "Bad gateway", "time": time.Now().Unix()})
	}

	// Copy response headers
	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if k != "Content-Length" && k != "Transfer-Encoding" && k != "Connection" {
			c.Set(k, string(value))
		}
	})

	// Handle caching
	if route.CacheTTL > 0 && c.Method() == "GET" {
		c.Set("X-Cache", "MISS")
		if resp.StatusCode() == 200 {
			cacheData := &CacheData{
				Body:       make([]byte, len(resp.Body())),
				Headers:    gw.extractHeaders(resp),
				StatusCode: resp.StatusCode(),
			}
			copy(cacheData.Body, resp.Body())
			go gw.setCache(gw.cacheKey(c), cacheData, time.Duration(route.CacheTTL)*time.Second)
		}
	}

	return c.Status(resp.StatusCode()).Send(resp.Body())
}

// Fix: Rate limiting logic
func (gw *Gateway) CheckRateLimit(ip string, limit int) (bool, error) {
	key := fmt.Sprintf("rate_limit:%s", ip)
	pipe := gw.Redis.Pipeline()
	incr := pipe.Incr(gw.Ctx, key)
	pipe.Expire(gw.Ctx, key, time.Minute) // Fixed: 1 minute window
	_, err := pipe.Exec(gw.Ctx)
	if err != nil {
		log.Printf("Failed to check rate limit: %v", err)
		return false, err
	}

	count := incr.Val()
	return count > int64(limit), nil
}

func (gw *Gateway) jwtMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{
				"success": false,
				"error":   "Authorization Header required. Unauthorized",
			})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if strings.EqualFold(tokenString, authHeader) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error":   "Bearer token required",
			})
		}

		var claims *jwt.MapClaims
		var err error
		switch gw.Config.AuthType {
		case AWSCOGNITO:
			claims, err = gw.validateAWSCognitoToken(tokenString)
		case NORMAL:
			claims, err = gw.validateNormalToken(tokenString)
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   "Invalid auth type configuration",
			})
		}

		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error":   err.Error(),
			})
		}

		if err = gw.setUserClaims(c, claims); err != nil {
			log.Printf("Failed to set user claims cookie: %v", err)
		}

		c.Locals("jwt_claims", claims)
		return c.Next()
	}
}

// Fix: JWKS parsing
func (gw *Gateway) getPublicKeyFromJWKS(kid string) (*rsa.PublicKey, error) {
	cacheKey := fmt.Sprintf("jwks:%s", kid)
	if cached := gw.getJWKSFromCache(cacheKey); cached != nil {
		return cached, nil
	}

	resp, err := http.Get(gw.Config.AWSJWKS)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %v", err)
	}

	jwkSet, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	key, found := jwkSet.LookupKeyID(kid)
	if !found {
		return nil, fmt.Errorf("key with kid %s not found", kid)
	}

	var publicKey rsa.PublicKey
	if err := key.Raw(&publicKey); err != nil {
		return nil, fmt.Errorf("failed to convert to RSA public key: %v", err)
	}

	go gw.cacheJWKS(cacheKey, &publicKey, time.Hour)
	return &publicKey, nil
}

// Rest of the methods remain the same...
func (gw *Gateway) getCache(key string) *CacheData {
	val, err := gw.Redis.Get(gw.Ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		log.Printf("Cache get error: %v", err)
		return nil
	}

	var cached *CacheData
	err = json.Unmarshal([]byte(val), &cached)
	if err != nil {
		log.Printf("Cache unmarshal error: %v", err)
		return nil
	}
	return cached
}

func (gw *Gateway) setCache(key string, data *CacheData, ttl time.Duration) {
	val, err := json.Marshal(data)
	if err != nil {
		log.Printf("Cache marshal error: %v", err)
		return
	}
	gw.Redis.Set(gw.Ctx, key, string(val), ttl)
}

func (gw *Gateway) cacheKey(c *fiber.Ctx) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s", c.Method(), c.Path(), c.Request().URI().QueryString())))
	return fmt.Sprintf("cache:%x", h.Sum(nil))
}

func (gw *Gateway) getServicesFromRedis(serviceName string) []ServiceInstance {
	key := fmt.Sprintf("services:%s", serviceName)
	val, err := gw.Redis.Get(gw.Ctx, key).Result()
	if err != nil {
		return nil
	}

	var instances []ServiceInstance
	err = json.Unmarshal([]byte(val), &instances)
	if err != nil {
		log.Printf("Redis services unmarshal error: %v", err)
		return nil
	}
	return instances
}

func (gw *Gateway) setServicesInRedis(serviceName string, instances []ServiceInstance) {
	key := fmt.Sprintf("services:%s", serviceName)
	val, _ := json.Marshal(instances)
	gw.Redis.Set(gw.Ctx, key, val, 60*time.Second)
}

func (gw *Gateway) watchServices() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		<-ticker.C
		for _, route := range gw.Config.Routes {
			go gw.fetchFromConsul(route.Service)
		}
	}
}

func (gw *Gateway) getService(serviceName string) *ServiceInstance {
	log.Printf("Looking for service: %s", serviceName)

	if services, ok := gw.Services.Load(serviceName); ok {
		instances := services.([]ServiceInstance)
		log.Printf("Found %d instances in memory for %s", len(instances), serviceName)
		if len(instances) > 0 {
			return &instances[rand.Intn(len(instances))]
		}
	}

	if instances := gw.getServicesFromRedis(serviceName); len(instances) > 0 {
		log.Printf("Found %d instances in Redis for %s", len(instances), serviceName)
		gw.Services.Store(serviceName, instances)
		return &instances[rand.Intn(len(instances))]
	}

	log.Printf("Fetching from Consul for service: %s", serviceName)
	return gw.fetchFromConsul(serviceName)
}

func (gw *Gateway) fetchFromConsul(serviceName string) *ServiceInstance {
	log.Printf("Consul fetch for service: %s", serviceName)
	services, _, err := gw.Consult.Health().Service(serviceName, "", true, nil)
	if err != nil {
		log.Printf("Consul error for %s: %v", serviceName, err)
		return nil
	}

	log.Printf("Consul returned %d services for %s", len(services), serviceName)
	if len(services) == 0 {
		return nil
	}

	instances := make([]ServiceInstance, len(services))
	for i, service := range services {
		instances[i] = ServiceInstance{
			Address: service.Service.Address,
			Port:    service.Service.Port,
		}
		log.Printf("Service instance: %s:%d", service.Service.Address, service.Service.Port)
	}

	gw.Services.Store(serviceName, instances)
	gw.setServicesInRedis(serviceName, instances)
	return &instances[rand.Intn(len(instances))]
}

func (gw *Gateway) extractHeaders(resp *fasthttp.Response) map[string]string {
	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		k, v := string(key), string(value)
		if k != "Content-Length" && k != "Transfer-Encoding" && k != "Connection" {
			headers[k] = v
		}
	})
	return headers
}

func (gw *Gateway) Start() error {
	log.Printf("Gateway starting on port %d", gw.Config.Port)
	log.Printf("Connected to Consul: %s", gw.Config.ConsulAddr)
	log.Printf("Connected to Redis: %s", gw.Config.RedisAddr)
	return gw.App.Listen(fmt.Sprintf(":%d", gw.Config.Port))
}

func (gw *Gateway) validateNormalToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(gw.Config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (gw *Gateway) validateAWSCognitoToken(tokenString string) (*jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid not found in token header")
	}

	publicKey, err := gw.getPublicKeyFromJWKS(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	validatedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := validatedToken.Claims.(jwt.MapClaims); ok && validatedToken.Valid {
		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (gw *Gateway) cacheJWKS(key string, publicKey *rsa.PublicKey, ttl time.Duration) {
	keyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return
	}
	gw.Redis.Set(gw.Ctx, key, base64.StdEncoding.EncodeToString(keyBytes), ttl)
}

func (gw *Gateway) getJWKSFromCache(key string) *rsa.PublicKey {
	val, err := gw.Redis.Get(gw.Ctx, key).Result()
	if err != nil {
		return nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil
	}

	var publicKey rsa.PublicKey
	if err := json.Unmarshal(keyBytes, &publicKey); err != nil {
		return nil
	}

	return &publicKey
}

func (gw *Gateway) setUserClaims(c *fiber.Ctx, claims *jwt.MapClaims) error {
	userInfo := gw.extractUserInfo(*claims)

	userInfoBytes, err := json.Marshal(userInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal user info: %v", err)
	}

	encodedUserInfo := base64.StdEncoding.EncodeToString(userInfoBytes)

	c.Cookie(&fiber.Cookie{
		Name:     "X-User-Claims",
		Value:    encodedUserInfo,
		HTTPOnly: true,
		Secure:   false,
		SameSite: "Strict",
		MaxAge:   3600,
	})

	return nil
}

func (gw *Gateway) extractUserInfo(claims jwt.MapClaims) map[string]interface{} {
	userInfo := make(map[string]interface{})

	// Standard claims
	if sub, ok := claims["sub"]; ok {
		userInfo["user_id"] = sub
	}
	if email, ok := claims["email"]; ok {
		userInfo["email"] = email
	}
	if username, ok := claims["username"]; ok {
		userInfo["username"] = username
	}
	if name, ok := claims["name"]; ok {
		userInfo["name"] = name
	}

	// AWS Cognito specific claims
	if cognitoUsername, ok := claims["cognito:username"]; ok {
		userInfo["cognito_username"] = cognitoUsername
	}
	if groups, ok := claims["cognito:groups"]; ok {
		userInfo["groups"] = groups
	}

	// Custom claims
	if roles, ok := claims["roles"]; ok {
		userInfo["roles"] = roles
	}
	if permissions, ok := claims["permissions"]; ok {
		userInfo["permissions"] = permissions
	}

	if exp, ok := claims["exp"]; ok {
		userInfo["exp"] = exp
	}

	return userInfo
}

func GetUserClaimsFromCookie(cookieValue string) (map[string]interface{}, error) {
	if cookieValue == "" {
		return nil, fmt.Errorf("no user claims cookie found")
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user claims: %v", err)
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user claims: %v", err)
	}

	return userInfo, nil
}
