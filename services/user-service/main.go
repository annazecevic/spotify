package main

import (
	"context"
	"log"
	"time"

	"github.com/annazecevic/user-service/config"
	"github.com/annazecevic/user-service/handler"
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer client.Disconnect(context.Background())

	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}
	log.Println("Connected to MongoDB successfully")

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
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		// Security headers (2.18)
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

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
		}
	}

	log.Printf("Starting server on port %s", cfg.ServerPort)
	if err := router.Run(":" + cfg.ServerPort); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
