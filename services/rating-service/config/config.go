package config

import (
	"os"
	"strconv"
)

type Config struct {
	MongoURI      string
	MongoDatabase string
	ServerPort    string
	Environment   string

	JWTSecret string

	UserServiceURL    string
	ContentServiceURL string

	LogFilePath   string
	LogHMACKey    string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func LoadConfig() *Config {
	return &Config{
		MongoURI:      getEnv("MONGO_URI", "mongodb://rating-mongodb:27017"),
		MongoDatabase: getEnv("MONGO_DATABASE", "spotify_ratings"),
		ServerPort:    getEnv("SERVER_PORT", "8084"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		JWTSecret:     getEnv("JWT_SECRET", "your-secret-key-change-in-production"),

		UserServiceURL:    getEnv("USER_SERVICE_URL", "http://user-service:8080"),
		ContentServiceURL: getEnv("CONTENT_SERVICE_URL", "http://content-service:8081"),

		LogFilePath:   getEnv("LOG_FILE_PATH", "/var/log/rating-service/app.log"),
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
