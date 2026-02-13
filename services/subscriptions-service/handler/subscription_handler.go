package handler

import (
	"net/http"

	"github.com/annazecevic/subscriptions-service/domain"
	"github.com/annazecevic/subscriptions-service/dto"
	"github.com/annazecevic/subscriptions-service/logger"
	"github.com/annazecevic/subscriptions-service/middleware"
	"github.com/annazecevic/subscriptions-service/service"
	"github.com/gin-gonic/gin"
)

type SubscriptionHandler struct {
	service service.SubscriptionService
}

func NewSubscriptionHandler(service service.SubscriptionService) *SubscriptionHandler {
	return &SubscriptionHandler{
		service: service,
	}
}

func (h *SubscriptionHandler) Subscribe(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req dto.CreateSubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid subscription request", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: type must be ARTIST or GENRE, target_id is required"})
		return
	}

	authToken := c.GetHeader("Authorization")
	subType := domain.SubscriptionType(req.Type)

	subscription, err := h.service.Subscribe(userID, subType, req.TargetID, authToken)
	if err != nil {
		if err.Error() == "already subscribed to this content" {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if err.Error() == "target content not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		logger.Error(logger.EventGeneral, "Failed to create subscription", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create subscription"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "successfully subscribed",
		"data":    toSubscriptionResponse(subscription),
	})
}

func (h *SubscriptionHandler) Unsubscribe(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	subscriptionID := c.Param("id")
	if subscriptionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subscription ID is required"})
		return
	}

	err := h.service.Unsubscribe(userID, subscriptionID)
	if err != nil {
		if err.Error() == "subscription not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "subscription not found"})
			return
		}
		logger.Error(logger.EventGeneral, "Failed to unsubscribe", logger.Fields(
			"user_id", userID,
			"subscription_id", subscriptionID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unsubscribe"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "successfully unsubscribed"})
}

func (h *SubscriptionHandler) GetMySubscriptions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	subTypeParam := c.Query("type")

	var subscriptions []domain.Subscription
	var err error

	if subTypeParam != "" {
		subType := domain.SubscriptionType(subTypeParam)
		if subType != domain.SubscriptionTypeArtist && subType != domain.SubscriptionTypeGenre {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid type: must be ARTIST or GENRE"})
			return
		}
		subscriptions, err = h.service.GetUserSubscriptionsByType(userID, subType)
	} else {
		subscriptions, err = h.service.GetUserSubscriptions(userID)
	}

	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch subscriptions", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subscriptions"})
		return
	}

	response := dto.SubscriptionsListResponse{
		Data:  toSubscriptionResponses(subscriptions),
		Count: len(subscriptions),
	}

	c.JSON(http.StatusOK, response)
}

func (h *SubscriptionHandler) CheckSubscription(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	targetID := c.Param("targetId")
	if targetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_id is required"})
		return
	}

	isSubscribed, err := h.service.CheckSubscription(userID, targetID)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to check subscription", logger.Fields(
			"user_id", userID,
			"target_id", targetID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check subscription"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"subscribed": isSubscribed})
}

func (h *SubscriptionHandler) GetSubscribers(c *gin.Context) {
	targetID := c.Param("targetId")
	subTypeParam := c.Query("type")

	if targetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_id is required"})
		return
	}

	subType := domain.SubscriptionType(subTypeParam)
	if subType != domain.SubscriptionTypeArtist && subType != domain.SubscriptionTypeGenre {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid type: must be ARTIST or GENRE"})
		return
	}

	subscriptions, err := h.service.GetSubscribersByTarget(targetID, subType)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch subscribers", logger.Fields(
			"target_id", targetID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subscribers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  toSubscriptionResponses(subscriptions),
		"count": len(subscriptions),
	})
}

func (h *SubscriptionHandler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		subscriptions := api.Group("/subscriptions")
		subscriptions.Use(middleware.AuthMiddleware())
		{
			subscriptions.POST("", h.Subscribe)
			subscriptions.GET("/me", h.GetMySubscriptions)
			subscriptions.DELETE("/:id", h.Unsubscribe)
			subscriptions.GET("/check/:targetId", h.CheckSubscription)
		}

		internal := api.Group("/internal/subscriptions")
		{
			internal.GET("/subscribers/:targetId", h.GetSubscribers)
		}
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func toSubscriptionResponse(sub *domain.Subscription) dto.SubscriptionResponse {
	return dto.SubscriptionResponse{
		ID:        sub.ID,
		UserID:    sub.UserID,
		Type:      string(sub.Type),
		TargetID:  sub.TargetID,
		Name:      sub.Name,
		CreatedAt: sub.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func toSubscriptionResponses(subs []domain.Subscription) []dto.SubscriptionResponse {
	responses := make([]dto.SubscriptionResponse, 0, len(subs))
	for _, sub := range subs {
		responses = append(responses, toSubscriptionResponse(&sub))
	}
	return responses
}
