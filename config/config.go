package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort        string
	DBHost            string
	DBUser            string
	DBPassword        string
	DBName            string
	DBPort            string
	JWTSecretKey      string
	StorageServiceURL string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	return &Config{
		ServerPort:        getEnv("SERVER_PORT", "8080"),
		DBHost:            getEnv("DB_HOST", "localhost"),
		DBUser:            getEnv("DB_USER", ""),
		DBPassword:        getEnv("DB_PASSWORD", ""),
		DBName:            getEnv("DB_NAME", ""),
		DBPort:            getEnv("DB_PORT", "5432"),
		JWTSecretKey:      getEnv("JWT_SECRET_KEY", ""),
		StorageServiceURL: getEnv("STORAGE_SERVICE_URL", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	if fallback == "" {
		log.Fatalf("FATAL: Environment variable %s is not set.", key)
	}
	return fallback
}
