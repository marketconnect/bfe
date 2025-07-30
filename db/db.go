package db

import (
	"fmt"
	"log"

	"github.com/marketconnect/bfe/config"
	"github.com/marketconnect/bfe/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Init(cfg *config.Config) *gorm.DB {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&models.User{}, &models.UserPermission{}); err != nil {
		log.Fatalf("Failed to auto-migrate database schema: %v", err)
	}

	return db
}
