package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware extracts user information from headers (set by nginx auth_request)
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user authentication"})
			return
		}

		role := c.GetHeader("X-User-Role")

		// Set user information in context
		c.Set("user_id", userID)
		c.Set("user_role", role)

		c.Next()
	}
}

// RoleMiddleware checks if user has required role (2.17 - authorization)
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "role information not found"})
			return
		}

		userRole, ok := role.(string)
		if !ok || userRole != requiredRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":         "insufficient permissions",
				"required_role": requiredRole,
			})
			return
		}

		c.Next()
	}
}

// AdminOnly is a convenience middleware for admin-only endpoints (2.17)
func AdminOnly() gin.HandlerFunc {
	return RoleMiddleware("admin")
}

