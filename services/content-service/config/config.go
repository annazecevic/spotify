package config

import (
	"os"
)

type Config struct {
	MongoURI   string
	MongoDB    string
	ServerPort string
}

func Load() *Config {
	c := &Config{
		MongoURI:   getEnv("MONGO_URI", "mongodb://mongodb:27017"),
		MongoDB:    getEnv("MONGO_DATABASE", "content_db"),
		ServerPort: getEnv("SERVER_PORT", "8081"),
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
