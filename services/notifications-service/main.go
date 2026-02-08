package main

import (
	"fmt"
	"time"

	"github.com/annazecevic/notifications-service/config"
	"github.com/annazecevic/notifications-service/handler"
	"github.com/annazecevic/notifications-service/logger"
	"github.com/annazecevic/notifications-service/repository"
	"github.com/annazecevic/notifications-service/service"
	"github.com/gin-gonic/gin"
	"github.com/gocql/gocql"
)

func main() {
	cfg := config.LoadConfig()

	logger.Init(logger.Config{
		ServiceName: "notifications-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "Notifications service starting", logger.Fields(
		"port", cfg.ServerPort,
		"environment", cfg.Environment,
	))

	cluster := gocql.NewCluster(cfg.CassandraHosts...)
	cluster.Keyspace = cfg.CassandraKeyspace
	cluster.Consistency = gocql.Quorum
	cluster.Timeout = 10 * time.Second
	cluster.ConnectTimeout = 10 * time.Second

	session, err := cluster.CreateSession()
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to Cassandra", logger.Fields("error", err.Error()))
	}
	defer session.Close()

	logger.Info(logger.EventDBConnection, "Connected to Cassandra successfully", nil)

	notificationRepo := repository.NewNotificationRepository(session)
	notificationService := service.NewNotificationService(notificationRepo)
	notificationHandler := handler.NewNotificationHandler(notificationService)

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Next()
	})

	notificationHandler.RegisterRoutes(router)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("address", addr))
	if err := router.Run(addr); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}
