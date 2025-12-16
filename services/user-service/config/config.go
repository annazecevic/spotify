package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	MongoURI      string
	MongoDatabase string
	ServerPort    string
	Environment   string
	JWTSecret     string
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	return &Config{
		MongoURI:      getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDatabase: getEnv("MONGO_DATABASE", "spotify_users"),
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		JWTSecret:     getEnv("JWT_SECRET", "secret"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
