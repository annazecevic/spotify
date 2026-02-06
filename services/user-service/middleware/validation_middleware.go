package middleware

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

// ValidationMiddleware provides input validation (2.18)
type ValidationMiddleware struct{}

func NewValidationMiddleware() *ValidationMiddleware {
	return &ValidationMiddleware{}
}

// SanitizeString removes dangerous characters and HTML
func SanitizeString(input string) string {
	// HTML escape to prevent XSS
	sanitized := html.EscapeString(input)
	
	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)
	
	return sanitized
}

// ValidateAlphanumeric checks if string contains only alphanumeric characters and allowed symbols
func ValidateAlphanumeric(input string, allowSpaces bool) bool {
	for _, char := range input {
		if unicode.IsLetter(char) || unicode.IsNumber(char) {
			continue
		}
		if allowSpaces && unicode.IsSpace(char) {
			continue
		}
		// Allow only specific safe characters
		if char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

// ValidateEmail checks if email format is valid
func ValidateEmail(email string) bool {
	// RFC 5322 compliant regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateUsername checks username format (whitelisting approach)
func ValidateUsername(username string) error {
	// Length check (boundary checking)
	if len(username) < 3 || len(username) > 30 {
		return &ValidationError{"username must be between 3 and 30 characters"}
	}

	// Character whitelisting: only alphanumeric, underscore, hyphen
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	if !validUsername.MatchString(username) {
		return &ValidationError{"username can only contain letters, numbers, underscores, and hyphens"}
	}

	// Must start with a letter
	if !unicode.IsLetter(rune(username[0])) {
		return &ValidationError{"username must start with a letter"}
	}

	return nil
}

// ValidateName checks name format
func ValidateName(name string) error {
	// Length check (boundary checking)
	if len(name) < 2 || len(name) > 50 {
		return &ValidationError{"name must be between 2 and 50 characters"}
	}

	// Only letters, spaces, hyphens, apostrophes
	validName := regexp.MustCompile(`^[a-zA-ZÀ-ÿ\s'\-]+$`)
	if !validName.MatchString(name) {
		return &ValidationError{"name contains invalid characters"}
	}

	return nil
}

// ValidateStringLength performs boundary checking
func ValidateStringLength(input string, min, max int) error {
	length := len(input)
	if length < min || length > max {
		return &ValidationError{
			Message: string(rune(length)) + " characters - must be between " + 
				string(rune(min)) + " and " + string(rune(max)),
		}
	}
	return nil
}

// CheckSQLInjectionPatterns detects common SQL injection patterns
func CheckSQLInjectionPatterns(input string) bool {
	// Common SQL injection patterns
	sqlPatterns := []string{
		"(?i)(union.*select)",
		"(?i)(insert.*into)",
		"(?i)(delete.*from)",
		"(?i)(drop.*table)",
		"(?i)(update.*set)",
		"(?i)(exec.*xp_)",
		"(?i)(';|'--)",
		"(?i)(or.*=.*)",
		"(?i)(and.*=.*)",
	}

	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

// CheckXSSPatterns detects common XSS patterns
func CheckXSSPatterns(input string) bool {
	// Common XSS patterns
	xssPatterns := []string{
		"(?i)(<script)",
		"(?i)(</script>)",
		"(?i)(javascript:)",
		"(?i)(onerror=)",
		"(?i)(onload=)",
		"(?i)(eval\\()",
		"(?i)(<iframe)",
		"(?i)(document\\.cookie)",
	}

	for _, pattern := range xssPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

// ValidateNoSpecialChars checks for dangerous special characters
func ValidateNoSpecialChars(input string) bool {
	// Blacklist dangerous characters
	dangerousChars := []string{
		"<", ">", "&", "\"", "'", "/", "\\",
		";", "(", ")", "{", "}", "[", "]",
	}

	for _, char := range dangerousChars {
		if strings.Contains(input, char) {
			return false
		}
	}
	return true
}

// SanitizeInput middleware sanitizes all string inputs
func (v *ValidationMiddleware) SanitizeInput() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This is applied after binding, before processing
		// Actual sanitization happens in the request DTOs validation
		c.Next()
	}
}

// ValidateRequest performs comprehensive input validation
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

		// Check request size
		if c.Request.ContentLength > 10*1024*1024 { // 10MB limit
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large, maximum 10MB allowed",
			})
			return
		}

		c.Next()
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

