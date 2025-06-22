package main

import (
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/hashicorp/consul/api"
	"github.com/joho/godotenv"
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/internal/handler"
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/internal/repository"
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/internal/service"
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/pkg/provider"
	"go.uber.org/fx"
	"gorm.io/gorm"
	"log"
	"os"
)

func registerRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello Fiber with DB and Consul!")
	})
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	fx.New(
		provider.Module,
		provider.DBModule,
		provider.ConsulModule,
		repository.Module,
		service.Module,
		handler.Module,
		fx.Invoke(func(
			lc fx.Lifecycle,
			p *provider.FiberProvider,
			db *gorm.DB,
			consul *api.Client,
			authHandler *handler.AuthHandler,
		) {
			registerRoutes(p.App)
			authHandler.RegisterRoutes()
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					p.Log.Info("Starting Fiber")
					p.Log.Infof("Listening on port %s", PORT)
					go func() {
						p.Log.Infof("DB Connected: %v", db != nil)
						p.Log.Infof("Consul Agent: %v", consul.Agent())

						if err := p.App.Listen(":8080"); err != nil {
							p.Log.Fatal(err)
						}
					}()
					return nil
				},
				OnStop: func(ctx context.Context) error {
					p.Log.Info("Shutting down...")
					return p.App.Shutdown()
				},
			})
		}),
	).Run()
}
