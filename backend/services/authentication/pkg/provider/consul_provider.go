package provider

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hashicorp/consul/api"
	"go.uber.org/fx"
)

func NewConsulClient() (*api.Client, error) {
	host := os.Getenv("CONSUL_ADDRESS")
	if host == "" {
		host = "http://consul:8500"
	}

	cfg := api.DefaultConfig()
	cfg.Address = host

	var client *api.Client
	var err error

	for i := 0; i < 10; i++ {
		client, err = api.NewClient(cfg)
		if err == nil {
			_, err = client.Agent().Self()
		}
		if err == nil {
			log.Println("✅ Connected to Consul")
			break
		}
		log.Printf("⏳ Retrying Consul connection (%d/10): %v", i+1, err)
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("❌ failed to connect to Consul: %w", err)
	}

	return client, nil
}

func RegisterWithConsul(client *api.Client) error {
	// Health check URL for your service
	health := os.Getenv("HEALTH_ENDPOINT")
	if health == "" {
		health = "http://auth-service:8080/health"
	}

	reg := &api.AgentServiceRegistration{
		ID:      "auth-service",
		Name:    "authentication",
		Port:    8080,
		Address: "auth-service",
		Check: &api.AgentServiceCheck{
			HTTP:     health,
			Interval: "10s",
			Timeout:  "3s",
		},
		Tags: []string{"go", "fiber", "fx"},
	}

	if err := client.Agent().ServiceRegister(reg); err != nil {
		log.Printf(" Failed to register service in Consul: %v", err)
		return err
	}

	log.Println(" Service registered with Consul")
	return nil
}

var ConsulModule = fx.Options(
	fx.Provide(NewConsulClient),
	fx.Invoke(func(client *api.Client) {
		if err := RegisterWithConsul(client); err != nil {
			panic(err)
		}
	}),
)
