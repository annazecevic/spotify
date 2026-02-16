package middleware

import (
	"html"
	"regexp"
	"strings"
)

func SanitizeString(input string) string {
	if CheckXSSPatterns(input) || CheckSQLInjectionPatterns(input) {
		return ""
	}
	sanitized := html.EscapeString(input)
	sanitized = strings.TrimSpace(sanitized)
	return sanitized
}

func CheckSQLInjectionPatterns(input string) bool {
	sqlPatterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(drop\s+table)`,
		`(?i)(truncate\s+)`,
		`(?i)(update\s+set)`,
		`(?i)(';\s*--)`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(or\s+'1'\s*=\s*'1)`,
		`(?i)(--\s*$)`,
		`(?i)(;\s*drop)`,
	}

	for _, pattern := range sqlPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}

func CheckXSSPatterns(input string) bool {
	xssPatterns := []string{
		`(?i)(<script)`,
		`(?i)(javascript:)`,
		`(?i)(onerror\s*=)`,
		`(?i)(onload\s*=)`,
		`(?i)(<iframe)`,
		`(?i)(onclick\s*=)`,
		`(?i)(onmouseover\s*=)`,
	}

	for _, pattern := range xssPatterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}
	return false
}
