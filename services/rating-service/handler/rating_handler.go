package handler

import (
	"net/http"

	"github.com/annazecevic/rating-service/domain"
	"github.com/annazecevic/rating-service/dto"
	"github.com/annazecevic/rating-service/logger"
	"github.com/annazecevic/rating-service/middleware"
	"github.com/annazecevic/rating-service/service"
	"github.com/gin-gonic/gin"
)

type RatingHandler struct {
	service service.RatingService
}

func NewRatingHandler(service service.RatingService) *RatingHandler {
	return &RatingHandler{
		service: service,
	}
}

// POST /ratings/:trackId
func (h *RatingHandler) CreateOrUpdateRating(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trackId is required"})
		return
	}

	var req dto.CreateOrUpdateRatingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid rating request", logger.Fields(
			"user_id", userID,
			"track_id", trackID,
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request, value is required and must be 1-5"})
		return
	}

	rating, err := h.service.CreateOrUpdateRating(c, trackID, req.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, toRatingResponse(rating))
}

// DELETE /ratings/:trackId
func (h *RatingHandler) DeleteRating(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trackId is required"})
		return
	}

	err := h.service.DeleteRating(c, trackID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "rating deleted successfully"})
}

// GET /ratings/:trackId/user
func (h *RatingHandler) GetUserRating(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trackId is required"})
		return
	}

	rating, err := h.service.GetUserRating(c, trackID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rating == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rating not found"})
		return
	}

	c.JSON(http.StatusOK, toRatingResponse(rating))
}

// GET /ratings/:trackId/average
func (h *RatingHandler) GetAverageRating(c *gin.Context) {
	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trackId is required"})
		return
	}

	avg, err := h.service.GetAverageRating(trackID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := dto.AverageRatingResponse{
		TrackID: trackID,
		Average: avg,
		Count:   0,
	}

	c.JSON(http.StatusOK, response)
}

// GET /ratings/:trackId/all
func (h *RatingHandler) GetAllRatingsForTrack(c *gin.Context) {
	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "trackId is required"})
		return
	}

	ratings, err := h.service.GetAllRatingsForTrack(trackID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var response []dto.RatingResponse
	for _, r := range ratings {
		response = append(response, toRatingResponse(r))
	}

	c.JSON(http.StatusOK, response)
}

// map domain.Rating -> dto.RatingResponse
func toRatingResponse(r *domain.Rating) dto.RatingResponse {
	return dto.RatingResponse{
		ID:        r.ID,
		UserID:    r.UserID,
		TrackID:   r.TrackID,
		Value:     r.Value,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

// Registracija ruta
func (h *RatingHandler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		ratings := api.Group("/ratings")
		ratings.Use(middleware.AuthMiddleware())
		{
			ratings.POST("/:trackId", h.CreateOrUpdateRating)
			ratings.DELETE("/:trackId", h.DeleteRating)
			ratings.GET("/:trackId/user", h.GetUserRating)
			ratings.GET("/:trackId/average", h.GetAverageRating)
			ratings.GET("/:trackId/all", h.GetAllRatingsForTrack)
		}
	}

	// health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
