package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/annazecevic/content-service/config"
	"github.com/annazecevic/content-service/handler"
	"github.com/annazecevic/content-service/logger"
	"github.com/annazecevic/content-service/middleware"
	"github.com/annazecevic/content-service/repository"
	"github.com/annazecevic/content-service/service"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	cfg := config.Load()

	logger.Init(logger.Config{
		ServiceName: "content-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "Content service starting", logger.Fields(
		"port", cfg.ServerPort,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to MongoDB", logger.Fields("error", err.Error()))
	}
	db := client.Database(cfg.MongoDB)

	logger.Info(logger.EventDBConnection, "Connected to MongoDB successfully", nil)

	repo := repository.NewContentRepository(db)
	svc := service.NewContentService(repo)
	h := handler.NewContentHandler(svc)

	r := gin.Default()

	// Security headers (2.18 - XSS protection)
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")
		c.Next()
	})

	// Validation middleware (2.18)
	validationMw := middleware.NewValidationMiddleware()
	r.Use(validationMw.ValidateRequest())

	// Rate limiting (2.17 - DoS protection)
	rateLimiter := middleware.NewRateLimiter(100, 1*time.Minute)
	r.Use(rateLimiter.Middleware())

	h.RegisterRoutes(r)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("address", addr))
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}
