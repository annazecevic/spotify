package main

import (
	"log"
	"storage-service/config"
	"storage-service/handler"
	"storage-service/hdfs"
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
		log.Printf("Failed to connect to HDFS (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(time.Duration(i+1) * 2 * time.Second)
	}
	return nil, err
}

func main() {
	cfg := config.Load()

	hdfsClient, err := connectWithRetry(cfg.HDFSNamenode, 10)
	if err != nil {
		log.Fatalf("Failed to connect to HDFS after retries: %v", err)
	}
	defer hdfsClient.Close()

	if err := hdfsClient.EnsureBaseDir(); err != nil {
		log.Fatalf("Failed to create base directory in HDFS: %v", err)
	}

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

	log.Printf("Storage service starting on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
