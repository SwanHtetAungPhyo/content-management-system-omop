package provider

import (
	"fmt"
	"go.uber.org/fx"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"os"
	"time"
)

func NewDatabase() (*gorm.DB, error) {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	name := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		host, user, password, name, port,
	)

	var db *gorm.DB
	var err error

	for i := 0; i < 10; i++ {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			log.Println(" Connected to PostgreSQL")
			return db, nil
		}
		log.Printf("⏳ Retry (%d/10) DB connection failed: %v", i+1, err)
		time.Sleep(3 * time.Second)
	}

	return nil, fmt.Errorf(" failed to connect to DB after retries: %w", err)
}

var DBModule = fx.Provide(NewDatabase)
