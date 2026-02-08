package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port         string
	HDFSNamenode string
	JWTSecret    string
	MaxFileSize  int64

	// Logging
	LogFilePath   string
	LogHMACKey    string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func Load() *Config {
	return &Config{
		Port:         getEnv("PORT", "8084"),
		HDFSNamenode: getEnv("HDFS_NAMENODE", "namenode:9000"),
		JWTSecret:    getEnv("JWT_SECRET", "your-secret-key"),
		MaxFileSize:  50 * 1024 * 1024, // 50MB max file size

		LogFilePath:   getEnv("LOG_FILE_PATH", "/var/log/storage-service/app.log"),
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
