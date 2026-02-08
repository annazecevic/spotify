package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	MongoURI      string
	MongoDatabase string
	ServerPort    string
	Environment   string
	JWTSecret     string
	SMTPHost      string
	SMTPPort      string
	SMTPUsername  string
	SMTPPassword  string
	SMTPFrom      string
	AppURL        string

	// Logging
	LogFilePath   string
	LogHMACKey    string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, using environment variables")
	}

	return &Config{
		MongoURI:      getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDatabase: getEnv("MONGO_DATABASE", "spotify_users"),
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		JWTSecret:     getEnv("JWT_SECRET", "secret"),
		SMTPHost:      getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:      getEnv("SMTP_PORT", "587"),
		SMTPUsername:  getEnv("SMTP_USERNAME", ""),
		SMTPPassword:  getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:      getEnv("SMTP_FROM", "noreply@spotify.com"),
		AppURL:        getEnv("APP_URL", "http://localhost:3000"),

		LogFilePath:   getEnv("LOG_FILE_PATH", "/var/log/user-service/app.log"),
		LogHMACKey:    getEnv("LOG_HMAC_KEY", "default-hmac-key-change-in-production"),
		LogMaxSizeMB:  getEnvAsInt("LOG_MAX_SIZE_MB", 100),
		LogMaxBackups: getEnvAsInt("LOG_MAX_BACKUPS", 5),
		LogMaxAgeDays: getEnvAsInt("LOG_MAX_AGE_DAYS", 30),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
