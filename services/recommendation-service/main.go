package main

import (
	"context"
	"fmt"
	"time"

	"github.com/annazecevic/recommendation-service/config"
	"github.com/annazecevic/recommendation-service/handler"
	"github.com/annazecevic/recommendation-service/logger"
	"github.com/annazecevic/recommendation-service/messaging"
	"github.com/annazecevic/recommendation-service/repository"
	"github.com/annazecevic/recommendation-service/resilience"
	"github.com/annazecevic/recommendation-service/service"
	"github.com/gin-gonic/gin"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	cfg := config.LoadConfig()

	logger.Init(logger.Config{
		ServiceName: "recommendation-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "Recommendation service starting", logger.Fields(
		"port", cfg.ServerPort,
		"environment", cfg.Environment,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	driver, err := neo4j.NewDriverWithContext(
		cfg.Neo4jURI,
		neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""),
	)
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to create Neo4j driver", logger.Fields("error", err.Error()))
	}

	if err := driver.VerifyConnectivity(ctx); err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to Neo4j", logger.Fields("error", err.Error()))
	}

	defer func() {
		if err := driver.Close(context.Background()); err != nil {
			logger.Error(logger.EventDBError, "Error closing Neo4j driver", logger.Fields("error", err.Error()))
		}
	}()

	logger.Info(logger.EventDBConnection, "Connected to Neo4j successfully", nil)

	createIndexes(ctx, driver)

	repo := repository.NewRecommendationRepository(driver)

	consumer, err := messaging.NewConsumer(cfg.NatsURL, repo)
	if err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to connect to NATS", logger.Fields("error", err.Error()))
	}
	defer consumer.Close()

	if err := consumer.Start(); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start NATS consumer", logger.Fields("error", err.Error()))
	}

	logger.Info(logger.EventGeneral, "NATS consumer started, listening for graph update events", nil)

	svc := service.NewRecommendationService(repo, cfg.ContentServiceURL, cfg.RatingServiceURL, cfg.SubscriptionsServiceURL)
	h := handler.NewRecommendationHandler(svc)

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

	router.Use(resilience.TimeoutMiddleware(15 * time.Second))

	h.RegisterRoutes(router)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("address", addr))
	if err := router.Run(addr); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}

func createIndexes(ctx context.Context, driver neo4j.DriverWithContext) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	indexes := []string{
		"CREATE INDEX user_id_index IF NOT EXISTS FOR (u:User) ON (u.id)",
		"CREATE INDEX track_id_index IF NOT EXISTS FOR (t:Track) ON (t.id)",
		"CREATE INDEX genre_id_index IF NOT EXISTS FOR (g:Genre) ON (g.id)",
		"CREATE INDEX genre_name_index IF NOT EXISTS FOR (g:Genre) ON (g.name)",
		"CREATE INDEX artist_id_index IF NOT EXISTS FOR (a:Artist) ON (a.id)",
	}

	for _, idx := range indexes {
		_, err := session.Run(ctx, idx, nil)
		if err != nil {
			logger.Warn(logger.EventDBError, "Failed to create index", logger.Fields("query", idx, "error", err.Error()))
		}
	}

	logger.Info(logger.EventGeneral, "Neo4j indexes created/verified", nil)
}
