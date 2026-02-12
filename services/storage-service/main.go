package main

import (
	"storage-service/config"
	"storage-service/handler"
	"storage-service/hdfs"
	"storage-service/logger"
	"storage-service/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func connectWithRetry(namenodeAddr string, maxRetries int) (*hdfs.Client, error) {
	var hdfsClient *hdfs.Client
	var err error

	for i := 0; i < maxRetries; i++ {
		hdfsClient, err = hdfs.NewClient(namenodeAddr)
		if err == nil {
			return hdfsClient, nil
		}
		logger.Warn(logger.EventDBError, "Failed to connect to HDFS, retrying", logger.Fields(
			"attempt", i+1,
			"max_retries", maxRetries,
			"error", err.Error(),
		))
		time.Sleep(time.Duration(i+1) * 2 * time.Second)
	}
	return nil, err
}

func main() {
	cfg := config.Load()

	logger.Init(logger.Config{
		ServiceName: "storage-service",
		Environment: cfg.Environment,
		LogFilePath: cfg.LogFilePath,
		HMACKey:     cfg.LogHMACKey,
		MaxSizeMB:   cfg.LogMaxSizeMB,
		MaxBackups:  cfg.LogMaxBackups,
		MaxAgeDays:  cfg.LogMaxAgeDays,
	})

	logger.Info(logger.EventServiceStartup, "Storage service starting", logger.Fields(
		"port", cfg.Port,
	))

	hdfsClient, err := connectWithRetry(cfg.HDFSNamenode, 10)
	if err != nil {
		logger.Fatal(logger.EventDBError, "Failed to connect to HDFS after retries", logger.Fields("error", err.Error()))
	}
	defer hdfsClient.Close()

	if err := hdfsClient.EnsureBaseDir(); err != nil {
		logger.Fatal(logger.EventDBError, "Failed to create base directory in HDFS", logger.Fields("error", err.Error()))
	}

	logger.Info(logger.EventDBConnection, "Connected to HDFS successfully", nil)

	storageHandler := handler.NewStorageHandler(hdfsClient)

	r := gin.Default()

	r.Use(middleware.RateLimiter())

	public := r.Group("/storage")
	{
		public.GET("/stream/:trackId", storageHandler.StreamTrack)
		public.HEAD("/stream/:trackId", storageHandler.GetTrackInfo)
	}

	protected := r.Group("/storage")
	protected.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	{
		protected.POST("/upload", storageHandler.UploadTrack)
		protected.DELETE("/:trackId", storageHandler.DeleteTrack)
	}

	admin := r.Group("/storage/admin")
	admin.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	admin.Use(middleware.AdminOnly())
	{
		admin.GET("/stats", storageHandler.GetStats)
	}

	logger.Info(logger.EventServiceStartup, "Server starting", logger.Fields("port", cfg.Port))
	if err := r.Run(":" + cfg.Port); err != nil {
		logger.Fatal(logger.EventGeneral, "Failed to start server", logger.Fields("error", err.Error()))
	}
}
