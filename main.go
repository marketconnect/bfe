package main

import (
	"fmt"
	"log"

	"github.com/marketconnect/bfe/api"
	"github.com/marketconnect/bfe/config"
	"github.com/marketconnect/bfe/db"
	"github.com/marketconnect/bfe/storage_client"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	database := db.Init(cfg)
	store := &db.GormStore{DB: database}

	storageClient := storage_client.NewClient(cfg.StorageServiceURL)

	handler := &api.Handler{
		Store:         store,
		StorageClient: storageClient,
		JwtSecret:     cfg.JWTSecretKey,
	}

	router := gin.Default()

	// Public routes
	router.POST("/login", handler.LoginHandler)

	// Authenticated routes
	authRoutes := router.Group("/")
	authRoutes.Use(api.AuthMiddleware(cfg.JWTSecretKey))
	{
		// User routes
		authRoutes.GET("/files", handler.ListFilesHandler)

		// Admin routes
		adminRoutes := authRoutes.Group("/admin")
		adminRoutes.Use(api.AdminMiddleware())
		{
			adminRoutes.POST("/users", handler.CreateUserHandler)
			adminRoutes.POST("/permissions", handler.AssignPermissionHandler)
		}
	}

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Starting main service on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
