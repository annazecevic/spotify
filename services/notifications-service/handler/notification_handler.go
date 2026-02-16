package handler

import (
	"net/http"
	"net/url"

	"github.com/annazecevic/notifications-service/logger"
	"github.com/annazecevic/notifications-service/middleware"
	"github.com/annazecevic/notifications-service/service"
	"github.com/gin-gonic/gin"
)

type NotificationHandler struct {
	service service.NotificationService
}

func NewNotificationHandler(service service.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		service: service,
	}
}

func (h *NotificationHandler) GetUserNotifications(c *gin.Context) {
	rawQuery, _ := url.QueryUnescape(c.Request.URL.RawQuery)
	if middleware.CheckXSSPatterns(rawQuery) || middleware.CheckSQLInjectionPatterns(rawQuery) {
		logger.Warn(logger.EventValidationFailure, "Malicious pattern detected in query string", logger.Fields(
			"ip", c.ClientIP(),
			"raw_query", rawQuery,
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or potentially malicious input detected"})
		return
	}

	queryUserID := c.Query("user_id")
	if queryUserID != "" {
		if middleware.CheckXSSPatterns(queryUserID) || middleware.CheckSQLInjectionPatterns(queryUserID) {
			logger.Warn(logger.EventValidationFailure, "Malicious pattern detected in user_id query parameter", logger.Fields(
				"ip", c.ClientIP(),
				"user_id", queryUserID,
			))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or potentially malicious input detected"})
			return
		}
	}

	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		userID = queryUserID
	}
	if userID == "" {
		logger.Warn(logger.EventValidationFailure, "Missing user_id in notification request", logger.Fields(
			"ip", c.ClientIP(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	if middleware.CheckXSSPatterns(userID) || middleware.CheckSQLInjectionPatterns(userID) {
		logger.Warn(logger.EventValidationFailure, "Malicious pattern detected in user_id", logger.Fields(
			"ip", c.ClientIP(),
			"user_id", userID,
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or potentially malicious input detected"})
		return
	}

	userID = middleware.SanitizeString(userID)
	if userID == "" {
		logger.Warn(logger.EventValidationFailure, "user_id became empty after sanitization", logger.Fields(
			"ip", c.ClientIP(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	notifications, err := h.service.GetUserNotifications(userID)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch user notifications", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  notifications,
		"count": len(notifications),
	})
}

func (h *NotificationHandler) GetAllNotifications(c *gin.Context) {
	notifications, err := h.service.GetAllNotifications()
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch all notifications", logger.Fields(
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  notifications,
		"count": len(notifications),
	})
}

func (h *NotificationHandler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		notifications := api.Group("/notifications")
		{
			notifications.GET("", h.GetAllNotifications)
			notifications.GET("/me", h.GetUserNotifications)
		}
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}
