package config

import (
	"os"
	"strconv"
)

type Config struct {
	CassandraHosts    []string
	CassandraKeyspace string
	ServerPort        string
	Environment       string
	JWTSecret         string

	// Logging
	LogFilePath   string
	LogHMACKey    string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func LoadConfig() *Config {
	hosts := getEnv("CASSANDRA_HOSTS", "cassandra")
	keyspace := getEnv("CASSANDRA_KEYSPACE", "notifications")
	port := getEnv("SERVER_PORT", "8082")
	env := getEnv("ENVIRONMENT", "development")
	jwtSecret := getEnv("JWT_SECRET", "your-secret-key-change-in-production")

	return &Config{
		CassandraHosts:    []string{hosts},
		CassandraKeyspace: keyspace,
		ServerPort:        port,
		Environment:       env,
		JWTSecret:         jwtSecret,

		LogFilePath:   getEnv("LOG_FILE_PATH", "/var/log/notifications-service/app.log"),
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
