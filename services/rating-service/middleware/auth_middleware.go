package middleware

import (
	"net/http"

	"github.com/annazecevic/rating-service/logger"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			logger.Security(logger.EventInvalidToken,
				"Missing user authentication header",
				logger.Fields("ip", c.ClientIP()),
			)

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing user authentication",
			})
			return
		}

		role := c.GetHeader("X-User-Role")

		c.Set("user_id", userID)
		c.Set("user_role", role)

		c.Next()
	}
}
