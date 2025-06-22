package types

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/hashicorp/consul/api"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
	"sync"
)

type (
	Config struct {
		Port       int     `json:"port"`
		ConsulAddr string  `json:"consul_addr"`
		RedisAddr  string  `json:"redis_addr"`
		Routes     []Route `json:"routes"`
	}

	Route struct {
		Path      string `json:"path"`
		Service   string `json:"service"`
		RateLimit int    `json:"rate_limit"`
		CacheTTL  int    `json:"cache_ttl"`
	}

	Gateway struct {
	App        *fiber.App
	Consult    *api.Client
	Redis      *redis.Client
	Services   sync.Map
	Config     Config
	Ctx        context.Context
	HttpClient *fasthttp.Client
}
	CacheData struct {
		Body       []byte            `json:"body"`
		Headers    map[string]string `json:"headers"`
		StatusCode int               `json:"status_code"`
	}

	ServiceInstance struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
)
