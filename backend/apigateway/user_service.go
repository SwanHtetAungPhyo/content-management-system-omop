package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/hashicorp/consul/api"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var users = []User{
	{1, "John Doe", "john@example.com"},
	{2, "Jane Smith", "jane@example.com"},
}

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
		_ = client.Agent().ServiceDeregister(serviceID)
		os.Exit(0)
	}()

	// Initialize Fiber app
	app := fiber.New()

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/users", func(c *fiber.Ctx) error {
		return c.JSON(users)
	})

	app.Get("/users/:id", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		id, err := strconv.Atoi(idParam)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid user ID",
			})
		}

		for _, user := range users {
			if user.ID == id {
				return c.JSON(user)
			}
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	})

	log.Println("User Service starting on :8081")
	log.Fatal(app.Listen(":8081"))
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
