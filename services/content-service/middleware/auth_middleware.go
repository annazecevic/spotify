package middleware

import (
	"net/http"

	"github.com/annazecevic/content-service/logger"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware extracts user information from headers set by nginx auth_request
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			logger.Security(logger.EventInvalidToken, "Missing user authentication header", logger.Fields("ip", c.ClientIP()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user authentication"})
			return
		}

		role := c.GetHeader("X-User-Role")

		c.Set("user_id", userID)
		c.Set("user_role", role)

		c.Next()
	}
}

// RoleMiddleware checks if user has the required role
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			logger.Security(logger.EventAccessDenied, "Role information not found", logger.Fields(
				"ip", c.ClientIP(),
				"required_role", requiredRole,
			))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "role information not found"})
			return
		}

		userRole, ok := role.(string)
		if !ok || userRole != requiredRole {
			logger.Security(logger.EventAccessDenied, "Insufficient permissions", logger.Fields(
				"user_id", c.GetString("user_id"),
				"user_role", userRole,
				"required_role", requiredRole,
				"ip", c.ClientIP(),
			))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":         "insufficient permissions",
				"required_role": requiredRole,
			})
			return
		}

		c.Next()
	}
}

// AdminOnly is a convenience wrapper for RoleMiddleware("admin")
func AdminOnly() gin.HandlerFunc {
	return RoleMiddleware("admin")
}
