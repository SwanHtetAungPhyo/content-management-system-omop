package types

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hashicorp/consul/api"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
	"log"
	"math/rand"
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
	for _, route := range gw.Config.Routes {
		gw.App.All(route.Path, gw.createHandler(route))
	}
}
func (gw *Gateway) createHandler(route Route) fiber.Handler {
	return func(c *fiber.Ctx) error {
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
	target := fmt.Sprintf("http://%s:%d%s", service.Address, service.Port, strings.TrimPrefix(c.Path(), "/api/users"))
	if len(c.Request().URI().QueryString()) > 0 {
		target += "?" + string(c.Request().URI().QueryString())
	}

	req.Header.SetMethod(c.Method())
	req.SetRequestURI(target)
	c.Request().Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if k != "Host" && k != "Connection" && k != "Content-Length" {
			req.Header.SetBytesKV(key, value)
		}
	})
	if c.Method() == "POST" || c.Method() == "PUT" || c.Method() == "PATCH" {
		req.SetBody(c.Body())
	}
	err := gw.HttpClient.Do(req, resp)
	if err != nil {
		return c.Status(502).JSON(fiber.Map{"status": "Bad gateway", "time": time.Now().Unix()})
	}

	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		if k != "Content-Length" && k != "Transfer-Encoding" && k != "Connection" {
			c.Set(k, string(value))
		}
	})

	if route.CacheTTL > 0 && c.Method() == "GET" {
		c.Set("X-Cache", "MISS")
	}
	if route.CacheTTL > 0 && c.Method() == "GET" && resp.StatusCode() == 200 {
		cacheData := &CacheData{
			Body:       make([]byte, len(resp.Body())),
			Headers:    gw.extractHeaders(resp),
			StatusCode: resp.StatusCode(),
		}
		copy(cacheData.Body, resp.Body())

		go gw.setCache(gw.cacheKey(c), cacheData, time.Duration(route.CacheTTL)*time.Second)
	}
	return c.Status(resp.StatusCode()).Send(resp.Body())
}
func (gw *Gateway) CheckRateLimit(ip string, limit int) (bool, error) {
	key := fmt.Sprintf("rate_limit:%s", ip)
	pipe := gw.Redis.Pipeline()
	incr := pipe.Incr(gw.Ctx, key)
	pipe.Expire(gw.Ctx, key, time.Duration(limit)*time.Minute)
	_, err := pipe.Exec(gw.Ctx)
	if err != nil {
		log.Printf("Failed to check rate limit: %v", &err)
		return false, err
	}

	count := incr.Val()
	return count > int64(limit), nil
}

func (gw *Gateway) getCache(key string) *CacheData {
	val, err := gw.Redis.Get(gw.Ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		log.Println("redis cache miss")
		return nil
	}
	var cached *CacheData
	err = json.Unmarshal([]byte(val), &cached)
	if err != nil {
		log.Println("redis cache miss")
		return nil
	}
	return cached
}

func (gw *Gateway) setCache(key string, data *CacheData, ttl time.Duration) {
	val, err := json.Marshal(data)
	if err != nil {
		log.Println("redis cache miss")
		return
	}
	gw.Redis.Set(gw.Ctx, key, string(val), ttl)
}

func (gw *Gateway) cacheKey(c *fiber.Ctx) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%s", c.Method(), c.Path(), c.Request().URI().QueryString())))
	return fmt.Sprintf("cache:%x", h.Sum(nil))
}

func (gw *Gateway) responseHeaders(c *fiber.Ctx) map[string]string {
	headers := make(map[string]string)
	c.Response().Header.VisitAll(func(key []byte, value []byte) {
		k, v := string(key), string(value)
		if k != "Content-Length" && k != "Transfer-Encoding" {
			headers[k] = v
		}
	})
	return headers
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
		log.Println("redis cache miss for services")
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
