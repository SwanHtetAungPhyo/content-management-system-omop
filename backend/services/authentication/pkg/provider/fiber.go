package provider

import (
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
)

type FiberProvider struct {
	App *fiber.App
	Log *logrus.Logger
}

func NewFiberApp() *fiber.App {
	return fiber.New()
}

func NewLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	return logger
}

func NewFiberProvider(app *fiber.App, log *logrus.Logger) *FiberProvider {
	return &FiberProvider{
		App: app,
		Log: log,
	}
}

var Module = fx.Options(
	fx.Provide(
		NewFiberApp,
		NewLogger,
		NewFiberProvider,
	),
)
