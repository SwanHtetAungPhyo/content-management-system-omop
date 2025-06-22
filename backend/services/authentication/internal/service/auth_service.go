package service

import (
	"github.com/orgs/one-project-one-month/repositories/cms/authentication/internal/repository"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
)

var Module = fx.Option(fx.Provide(
	NewAuthService,
))

type AuthService struct {
	log  *logrus.Logger
	repo *repository.AuthRepository
}

func NewAuthService(
	log *logrus.Logger,
	repo *repository.AuthRepository,
) *AuthService {
	return &AuthService{
		repo: repo,
		log:  log,
	}
}
