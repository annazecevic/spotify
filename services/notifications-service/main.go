package main

import (
	"fmt"
	"log"
	"time"

	"github.com/annazecevic/notifications-service/config"
	"github.com/annazecevic/notifications-service/handler"
	"github.com/annazecevic/notifications-service/repository"
	"github.com/annazecevic/notifications-service/service"
	"github.com/gin-gonic/gin"
	"github.com/gocql/gocql"
)

func main() {
	cfg := config.LoadConfig()

	cluster := gocql.NewCluster(cfg.CassandraHosts...)
	cluster.Keyspace = cfg.CassandraKeyspace
	cluster.Consistency = gocql.Quorum
	cluster.Timeout = 10 * time.Second
	cluster.ConnectTimeout = 10 * time.Second

	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal("Failed to connect to Cassandra:", err)
	}
	defer session.Close()

	log.Println("Connected to Cassandra successfully")

	notificationRepo := repository.NewNotificationRepository(session)
	notificationService := service.NewNotificationService(notificationRepo)
	notificationHandler := handler.NewNotificationHandler(notificationService)

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	notificationHandler.RegisterRoutes(router)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	log.Printf("Starting notifications-service on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
