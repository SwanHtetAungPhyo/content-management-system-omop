package repository

import (
	"go.uber.org/fx"
	"gorm.io/gorm"
)

var Module = fx.Option(fx.Provide(
	NewAuthRepository,
))

type AuthRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{db: db}

}
