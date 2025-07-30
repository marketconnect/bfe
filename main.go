package main

import (
	"fmt"
	"log"

	"gorm.io/gorm"

	"github.com/marketconnect/bfe/api"
	"github.com/marketconnect/bfe/config"
	"github.com/marketconnect/bfe/db"
	"github.com/marketconnect/bfe/models"
	"github.com/marketconnect/bfe/storage_client"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	cfg := config.Load()

	database := db.Init(cfg)
	store := &db.GormStore{DB: database}

	seedAdminUser(store, cfg)

	storageClient := storage_client.NewClient(cfg.StorageServiceURL)

	handler := &api.Handler{
		Store:         store,
		StorageClient: storageClient,
		JwtSecret:     cfg.JWTSecretKey,
	}

	router := gin.Default()

	config := cors.DefaultConfig()

	config.AllowOrigins = []string{"http://localhost:3000"}

	config.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}

	router.Use(cors.New(config))

	apiV1 := router.Group("/api/v1")
	{
		// Public auth route
		authGroup := apiV1.Group("/auth")
		authGroup.POST("/login", handler.LoginHandler)

		// Authenticated routes
		authedRoutes := apiV1.Group("/")
		authedRoutes.Use(api.AuthMiddleware(cfg.JWTSecretKey))
		{
			// User routes
			authedRoutes.GET("/files", handler.ListFilesHandler)

			// Admin routes
			adminRoutes := authedRoutes.Group("/admin")
			adminRoutes.Use(api.AdminMiddleware())
			{
				adminRoutes.PUT("/self", handler.UpdateAdminSelfHandler)
				adminRoutes.GET("/users", handler.ListUsersHandler)
				adminRoutes.POST("/users", handler.CreateUserHandler)
				adminRoutes.DELETE("/users/:id", handler.DeleteUserHandler)
				adminRoutes.POST("/permissions", handler.AssignPermissionHandler)
				adminRoutes.DELETE("/permissions/:id", handler.RevokePermissionHandler)
				adminRoutes.GET("/storage/folders", handler.ListAllFoldersHandler)
			}
		}
	}

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Starting main service on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func seedAdminUser(store db.Store, cfg *config.Config) {
	if cfg.AdminPassword == "" {
		log.Println("ADMIN_PASSWORD is not set, skipping admin user seeding.")
		return
	}

	_, err := store.GetUserByUsername(cfg.AdminUser)
	if err == nil {
		// User already exists
		log.Println("Admin user already exists.")
		return
	}

	if err != gorm.ErrRecordNotFound {
		log.Printf("Error checking for admin user: %v. Skipping seed.", err)
		return
	}

	// User not found, create it
	log.Println("Admin user not found, creating...")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	admin := &models.User{Username: cfg.AdminUser, PasswordHash: string(hashedPassword), IsAdmin: true}
	if err := store.CreateUser(admin); err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}
	log.Printf("Admin user '%s' created successfully.", cfg.AdminUser)
}
