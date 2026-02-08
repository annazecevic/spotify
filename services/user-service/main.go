package main

import (
	"context"
	"time"

	"github.com/annazecevic/user-service/config"
	"github.com/annazecevic/user-service/handler"
	"github.com/annazecevic/user-service/logger"
	"github.com/annazecevic/user-service/middleware"
	"github.com/annazecevic/user-service/repository"
	"github.com/annazecevic/user-service/service"
	"github.com/annazecevic/user-service/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	cfg := config.LoadConfig()

	logger.Init(logger.Config{
		ServiceName: "user-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "User service starting", logger.Fields(
		"port", cfg.ServerPort,
		"environment", cfg.Environment,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to MongoDB", logger.Fields("error", err.Error()))
	}
	defer client.Disconnect(context.Background())

	if err := client.Ping(ctx, nil); err != nil {
		logger.Fatal(logger.EventDBError, "Failed to ping MongoDB", logger.Fields("error", err.Error()))
	}
	logger.Info(logger.EventDBConnection, "Connected to MongoDB successfully", nil)

	db := client.Database(cfg.MongoDatabase)

	emailService := utils.NewEmailService(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUsername,
		cfg.SMTPPassword,
		cfg.SMTPFrom,
		cfg.AppURL,
	)

	userRepo := repository.NewUserRepository(db)
	userService := service.NewUserService(userRepo, emailService)
	userHandler := handler.NewUserHandler(userService, cfg.JWTSecret)

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Security headers middleware (2.18 - XSS protection)
	router.Use(func(c *gin.Context) {
		// Security headers (2.18)
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")

		c.Next()
	})

	// Validation middleware (2.18)
	validationMw := middleware.NewValidationMiddleware()
	router.Use(validationMw.ValidateRequest())

	// Rate limiter for general endpoints (2.17 - DoS protection)
	generalRateLimiter := middleware.NewRateLimiter(100, 1*time.Minute)
	router.Use(generalRateLimiter.Middleware())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	router.GET("/internal/validate", userHandler.ValidateToken)

	// Strict rate limiter for auth endpoints (2.17 - DoS protection)
	authRateLimiter := middleware.NewRateLimiter(5, 1*time.Minute)

	api := router.Group("/api/v1")
	{
		users := api.Group("/users")
		{
			// Public endpoints with strict rate limiting
			users.POST("/register", authRateLimiter.Middleware(), userHandler.Register)
			users.POST("/login", authRateLimiter.Middleware(), userHandler.Login)
			users.POST("/verify-otp", authRateLimiter.Middleware(), userHandler.VerifyOTP)
			users.GET("/confirm", userHandler.ConfirmEmail)
			users.POST("/confirm", userHandler.ConfirmEmail)
			users.POST("/password-reset/request", authRateLimiter.Middleware(), userHandler.RequestPasswordReset)
			users.POST("/password-reset/reset", authRateLimiter.Middleware(), userHandler.ResetPassword)
			users.POST("/magic-link/request", authRateLimiter.Middleware(), userHandler.RequestMagicLink)
			users.GET("/magic-link/verify", userHandler.VerifyMagicLink)
			users.POST("/magic-link/verify", userHandler.VerifyMagicLink)

			// Protected endpoints (2.17 - authorization)
			users.GET("/me", middleware.AuthMiddleware(cfg.JWTSecret), userHandler.Me)
			users.PUT("/me", middleware.AuthMiddleware(cfg.JWTSecret), userHandler.UpdateProfile)
			users.POST("/change-password", middleware.AuthMiddleware(cfg.JWTSecret), userHandler.ChangePassword)
		}
	}

	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("port", cfg.ServerPort))
	if err := router.Run(":" + cfg.ServerPort); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}
