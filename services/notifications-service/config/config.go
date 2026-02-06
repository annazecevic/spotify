package config

import (
	"os"
)

type Config struct {
	CassandraHosts    []string
	CassandraKeyspace string
	ServerPort        string
	Environment       string
	JWTSecret         string
}

func LoadConfig() *Config {
	hosts := os.Getenv("CASSANDRA_HOSTS")
	if hosts == "" {
		hosts = "cassandra"
	}

	keyspace := os.Getenv("CASSANDRA_KEYSPACE")
	if keyspace == "" {
		keyspace = "notifications"
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8082"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key-change-in-production"
	}

	return &Config{
		CassandraHosts:    []string{hosts},
		CassandraKeyspace: keyspace,
		ServerPort:        port,
		Environment:       env,
		JWTSecret:         jwtSecret,
	}
}
