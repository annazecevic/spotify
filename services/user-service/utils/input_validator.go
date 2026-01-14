package utils

import (
	"errors"
	"html"
	"regexp"
	"strings"
	"unicode"
)

// SanitizeInput performs HTML escaping and trimming (2.18 - output encoding)
func SanitizeInput(input string) string {
	// HTML escape to prevent XSS
	sanitized := html.EscapeString(input)
	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)
	return sanitized
}

// ValidateUsername validates username with whitelisting approach (2.18)
func ValidateUsername(username string) error {
	// Boundary checking
	if len(username) < 3 || len(username) > 30 {
		return errors.New("username must be between 3 and 30 characters")
	}

	// Whitelisting: only alphanumeric, underscore, hyphen
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	if !validPattern.MatchString(username) {
		return errors.New("username can only contain letters, numbers, underscores, and hyphens")
	}

	// Must start with a letter
	if !unicode.IsLetter(rune(username[0])) {
		return errors.New("username must start with a letter")
	}

	// Check for SQL injection patterns
	if containsSQLInjection(username) {
		return errors.New("username contains invalid patterns")
	}

	return nil
}

// ValidateName validates name fields (2.18)
func ValidateName(name string) error {
	// Boundary checking
	if len(name) < 2 || len(name) > 50 {
		return errors.New("name must be between 2 and 50 characters")
	}

	// Whitelisting: letters, spaces, hyphens, apostrophes, unicode letters
	validPattern := regexp.MustCompile(`^[a-zA-ZÀ-ÿ\s'\-]+$`)
	if !validPattern.MatchString(name) {
		return errors.New("name contains invalid characters")
	}

	return nil
}

// ValidateEmail validates email format (2.18)
func ValidateEmail(email string) error {
	// Boundary checking
	if len(email) < 5 || len(email) > 254 {
		return errors.New("email must be between 5 and 254 characters")
	}

	// RFC 5322 compliant regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}

	// Additional checks
	if strings.Contains(email, "..") {
		return errors.New("email contains consecutive dots")
	}

	return nil
}

// ValidateNumericRange validates numeric values within boundaries (2.18)
func ValidateNumericRange(value, min, max int) error {
	if value < min || value > max {
		return errors.New("value out of allowed range")
	}
	return nil
}

// ValidateStringLength performs boundary checking (2.18)
func ValidateStringLength(input string, min, max int) error {
	length := len(input)
	if length < min || length > max {
		return errors.New("string length out of bounds")
	}
	return nil
}

// containsSQLInjection checks for SQL injection patterns (2.18)
func containsSQLInjection(input string) bool {
	sqlPatterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(drop\s+table)`,
		`(?i)(update\s+set)`,
		`(?i)(exec\s+xp_)`,
		`(?i)(';\s*--)`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
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
		`(?i)(</script>)`,
		`(?i)(javascript:)`,
		`(?i)(onerror\s*=)`,
		`(?i)(onload\s*=)`,
		`(?i)(eval\()`,
		`(?i)(<iframe)`,
		`(?i)(document\.cookie)`,
	}

	for _, pattern := range xssPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

// SanitizeHTML removes HTML tags and dangerous content (2.18)
func SanitizeHTML(input string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	sanitized := re.ReplaceAllString(input, "")
	
	// HTML escape
	sanitized = html.EscapeString(sanitized)
	
	return sanitized
}

