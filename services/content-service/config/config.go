package config

import (
	"os"
	"strconv"
)

type Config struct {
	MongoURI   string
	MongoDB    string
	ServerPort string

	// Logging
	LogFilePath   string
	LogHMACKey    string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func Load() *Config {
	c := &Config{
		MongoURI:   getEnv("MONGO_URI", "mongodb://mongodb:27017"),
		MongoDB:    getEnv("MONGO_DATABASE", "content_db"),
		ServerPort: getEnv("SERVER_PORT", "8081"),

		LogFilePath:   getEnv("LOG_FILE_PATH", "/var/log/content-service/app.log"),
		LogHMACKey:    getEnv("LOG_HMAC_KEY", "default-hmac-key-change-in-production"),
		LogMaxSizeMB:  getEnvAsInt("LOG_MAX_SIZE_MB", 100),
		LogMaxBackups: getEnvAsInt("LOG_MAX_BACKUPS", 5),
		LogMaxAgeDays: getEnvAsInt("LOG_MAX_AGE_DAYS", 30),
	}
	return c
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}
