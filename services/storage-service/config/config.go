package config

import (
	"os"
)

type Config struct {
	Port         string
	HDFSNamenode string
	JWTSecret    string
	MaxFileSize  int64
}

func Load() *Config {
	return &Config{
		Port:         getEnv("PORT", "8084"),
		HDFSNamenode: getEnv("HDFS_NAMENODE", "namenode:9000"),
		JWTSecret:    getEnv("JWT_SECRET", "your-secret-key"),
		MaxFileSize:  50 * 1024 * 1024, // 50MB max file size
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
