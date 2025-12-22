package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/annazecevic/content-service/config"
	"github.com/annazecevic/content-service/handler"
	"github.com/annazecevic/content-service/repository"
	"github.com/annazecevic/content-service/service"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
    cfg := config.Load()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
    if err != nil {
        log.Fatal("failed to connect to mongo:", err)
    }
    db := client.Database(cfg.MongoDB)

    repo := repository.NewContentRepository(db)
    svc := service.NewContentService(repo)
    h := handler.NewContentHandler(svc)

    r := gin.Default()
    h.RegisterRoutes(r)

    addr := fmt.Sprintf(":%s", cfg.ServerPort)
    log.Printf("Starting content-service on %s", addr)
    if err := http.ListenAndServe(addr, r); err != nil {
        log.Fatal(err)
    }
}
