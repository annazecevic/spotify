package middleware

import (
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// ValidationMiddleware provides input validation (2.18)
type ValidationMiddleware struct{}

func NewValidationMiddleware() *ValidationMiddleware {
	return &ValidationMiddleware{}
}

// ValidateRequest performs comprehensive input validation (2.18)
func (v *ValidationMiddleware) ValidateRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check content type for POST/PUT requests
		if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") && 
			   !strings.Contains(contentType, "multipart/form-data") {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": "invalid content type, expected application/json or multipart/form-data",
				})
				return
			}
		}

		// Check request size (boundary checking)
		if c.Request.ContentLength > 50*1024*1024 { // 50MB limit for audio files
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large, maximum 50MB allowed",
			})
			return
		}

		// Security headers (2.18 - XSS protection)
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")

		c.Next()
	}
}

// SanitizeString removes dangerous characters and HTML (2.18)
func SanitizeString(input string) string {
	// HTML escape to prevent XSS
	sanitized := html.EscapeString(input)
	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)
	return sanitized
}

// CheckSQLInjectionPatterns detects common SQL injection patterns (2.18)
func CheckSQLInjectionPatterns(input string) bool {
	sqlPatterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(drop\s+table)`,
		`(?i)(update\s+set)`,
		`(?i)(';\s*--)`,
		`(?i)(or\s+1\s*=\s*1)`,
	}

	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

// CheckXSSPatterns detects XSS patterns (2.18)
func CheckXSSPatterns(input string) bool {
	xssPatterns := []string{
		`(?i)(<script)`,
		`(?i)(javascript:)`,
		`(?i)(onerror\s*=)`,
		`(?i)(onload\s*=)`,
		`(?i)(<iframe)`,
	}

	for _, pattern := range xssPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

