package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/annazecevic/user-service/logger"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware validates JWT and extracts user information into context
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Security(logger.EventInvalidToken, "Missing authorization header", logger.Fields("ip", c.ClientIP()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Security(logger.EventInvalidToken, "Invalid authorization header format", logger.Fields("ip", c.ClientIP()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			if errors.Is(err, jwt.ErrTokenExpired) {
				logger.Security(logger.EventExpiredToken, "Access attempt with expired token", logger.Fields("ip", c.ClientIP()))
			} else {
				logger.Security(logger.EventInvalidToken, "Access attempt with invalid token", logger.Fields("ip", c.ClientIP()))
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logger.Security(logger.EventInvalidToken, "Token has invalid claims", logger.Fields("ip", c.ClientIP()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}

		userID, ok := claims["sub"].(string)
		if !ok || userID == "" {
			logger.Security(logger.EventInvalidToken, "Token missing user ID claim", logger.Fields("ip", c.ClientIP()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user ID in token"})
			return
		}

		role, _ := claims["role"].(string)

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
			logger.Security(logger.EventAccessDenied, "Role information not found in context", logger.Fields(
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
