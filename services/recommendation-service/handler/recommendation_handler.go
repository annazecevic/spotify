package handler

import (
	"net/http"

	"github.com/annazecevic/recommendation-service/dto"
	"github.com/annazecevic/recommendation-service/logger"
	"github.com/annazecevic/recommendation-service/middleware"
	"github.com/annazecevic/recommendation-service/service"
	"github.com/gin-gonic/gin"
)

type RecommendationHandler struct {
	service service.RecommendationService
}

func NewRecommendationHandler(service service.RecommendationService) *RecommendationHandler {
	return &RecommendationHandler{service: service}
}

func (h *RecommendationHandler) GetRecommendations(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	subscribedTracks, trendingTrack, err := h.service.GetRecommendations(c.Request.Context(), userID)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to get recommendations", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get recommendations"})
		return
	}

	total := len(subscribedTracks)
	if trendingTrack != nil {
		total++
	}

	response := dto.RecommendationResponse{
		SubscribedGenreTracks: subscribedTracks,
		TrendingTrack:         trendingTrack,
		Total:                 total,
	}

	logger.Info(logger.EventGeneral, "Recommendations generated", logger.Fields(
		"user_id", userID,
		"subscribed_tracks", len(subscribedTracks),
		"has_trending", trendingTrack != nil,
	))

	c.JSON(http.StatusOK, response)
}

func (h *RecommendationHandler) SyncData(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	if err := h.service.SyncAllData(c.Request.Context(), userID); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync data", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sync recommendation data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "data synced successfully"})
}

func (h *RecommendationHandler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		recommendations := api.Group("/recommendations")
		recommendations.Use(middleware.AuthMiddleware())
		{
			recommendations.GET("", h.GetRecommendations)
			recommendations.GET("/", h.GetRecommendations)
			recommendations.POST("/sync", h.SyncData)
		}
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
