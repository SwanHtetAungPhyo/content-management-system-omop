package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/internal/service"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
)

var Module = fx.Option(fx.Provide(
	NewAuthHandler,
))

type AuthHandler struct {
	srv *service.AuthService
	log *logrus.Logger
	app *fiber.App
}

func NewAuthHandler(
	log *logrus.Logger,
	srv *service.AuthService,
	fiber *fiber.App,
) *AuthHandler {
	return &AuthHandler{
		srv: srv,
		log: log,
		app: fiber,
	}
}

func (h *AuthHandler) RegisterRoutes() {
	h.app.Group("/auth")
	h.app.Get("/login", h.Login)
}

func (h *AuthHandler) Login(ctx *fiber.Ctx) error {
	return ctx.JSON(fiber.Map{
		"success": true,
	})
}
