package main

import (
	"context"
	"fmt"
	"time"

	"github.com/annazecevic/rating-service/config"
	"github.com/annazecevic/rating-service/handler"
	"github.com/annazecevic/rating-service/logger"
	"github.com/annazecevic/rating-service/repository"
	"github.com/annazecevic/rating-service/service"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {

	cfg := config.LoadConfig()

	logger.Init(logger.Config{
		ServiceName: "rating-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "Rating service starting", logger.Fields(
		"port", cfg.ServerPort,
		"environment", cfg.Environment,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	clientOpts := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to MongoDB", logger.Fields("error", err.Error()))
	}

	if err := client.Ping(ctx, nil); err != nil {
		logger.Fatal(logger.EventDBError, "Failed to ping MongoDB", logger.Fields("error", err.Error()))
	}

	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			logger.Error(logger.EventDBError, "Error disconnecting from MongoDB", logger.Fields("error", err.Error()))
		}
	}()

	logger.Info(logger.EventDBConnection, "Connected to MongoDB successfully", logger.Fields(
		"database", cfg.MongoDatabase,
	))

	db := client.Database(cfg.MongoDatabase)

	ratingRepo := repository.NewRatingRepository(db)
	ratingService := service.NewRatingService(ratingRepo, cfg.ContentServiceURL, cfg.UserServiceURL)
	ratingHandler := handler.NewRatingHandler(ratingService)

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()
	router.RedirectTrailingSlash = false

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Next()
	})

	ratingHandler.RegisterRoutes(router)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("address", addr))
	if err := router.Run(addr); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}
