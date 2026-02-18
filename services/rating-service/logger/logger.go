package logger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

type LogLevel string

const (
	LevelInfo     LogLevel = "INFO"
	LevelWarn     LogLevel = "WARN"
	LevelError    LogLevel = "ERROR"
	LevelSecurity LogLevel = "SECURITY"
)

const (
	EventValidationFailure = "VALIDATION_FAILURE"
	EventLoginSuccess      = "LOGIN_SUCCESS"
	EventLoginFailure      = "LOGIN_FAILURE"
	EventAccessDenied      = "ACCESS_DENIED"
	EventStateChange       = "UNEXPECTED_STATE_CHANGE"
	EventInvalidToken      = "INVALID_TOKEN"
	EventExpiredToken      = "EXPIRED_TOKEN"
	EventAdminActivity     = "ADMIN_ACTIVITY"
	EventTLSFailure        = "TLS_CONNECTION_FAILURE"
	EventServiceStartup    = "SERVICE_STARTUP"
	EventServiceShutdown   = "SERVICE_SHUTDOWN"
	EventDBConnection      = "DB_CONNECTION"
	EventDBError           = "DB_ERROR"
	EventGeneral           = "GENERAL"
)

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Service   string                 `json:"service"`
	EventType string                 `json:"event_type"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Hmac      string                 `json:"hmac"`
}

type Config struct {
	ServiceName string
	Environment string
	LogFilePath string
	HMACKey     string
	MaxSizeMB   int
	MaxBackups  int
	MaxAgeDays  int
}

type Logger struct {
	config  Config
	writer  io.Writer
	hmacKey []byte
	mu      sync.Mutex
}

var sensitiveFields = map[string]bool{
	"password":         true,
	"new_password":     true,
	"old_password":     true,
	"current_password": true,
	"confirm_password": true,
	"token":            true,
	"access_token":     true,
	"refresh_token":    true,
	"secret":           true,
	"authorization":    true,
	"cookie":           true,
	"otp":              true,
	"otp_code":         true,
	"credit_card":      true,
	"jwt":              true,
	"session_id":       true,
	"api_key":          true,
	"magic_link_token": true,
	"reset_token":      true,
}

var emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

var stackTraceIndicators = []string{
	"goroutine ",
	"\truntime/",
	"\tnet/http/",
	"runtime.goexit",
	"panic(",
}

var instance *Logger

func Init(cfg Config) {
	instance = NewLogger(cfg)
}

func GetLogger() *Logger {
	if instance == nil {
		instance = &Logger{
			config:  Config{ServiceName: "unknown", Environment: "development"},
			writer:  os.Stdout,
			hmacKey: []byte("default-key"),
		}
	}
	return instance
}

func NewLogger(cfg Config) *Logger {
	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays == 0 {
		cfg.MaxAgeDays = 30
	}
	if cfg.LogFilePath == "" {
		cfg.LogFilePath = fmt.Sprintf("/var/log/%s/app.log", cfg.ServiceName)
	}
	if cfg.HMACKey == "" {
		cfg.HMACKey = "default-hmac-key-change-in-production"
	}

	writers := []io.Writer{os.Stdout}

	logDir := filepath.Dir(cfg.LogFilePath)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Cannot create log directory %s: %v, using stdout only\n", logDir, err)
	} else {
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.LogFilePath,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   true,
		}
		writers = append(writers, fileWriter)
		ensureFilePermissions(cfg.LogFilePath)
	}
	return &Logger{
		config:  cfg,
		writer:  io.MultiWriter(writers...),
		hmacKey: []byte(cfg.HMACKey),
	}
}

func ensureFilePermissions(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		f.Close()
	}
	os.Chmod(path, 0600)
}

func (l *Logger) log(level LogLevel, eventType, message string, details map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Service:   l.config.ServiceName,
		EventType: eventType,
		Message:   l.sanitizeString(message),
		Details:   l.sanitizeDetails(details),
	}

	entry.Hmac = l.computeHMAC(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal log entry: %v\n", err)
		return
	}

	l.writer.Write(append(data, '\n'))
}

func (l *Logger) Info(eventType, message string, details map[string]interface{}) {
	l.log(LevelInfo, eventType, message, details)
}

func (l *Logger) Warn(eventType, message string, details map[string]interface{}) {
	l.log(LevelWarn, eventType, message, details)
}

func (l *Logger) Error(eventType, message string, details map[string]interface{}) {
	l.log(LevelError, eventType, message, details)
}

func (l *Logger) Security(eventType, message string, details map[string]interface{}) {
	l.log(LevelSecurity, eventType, message, details)
}

func (l *Logger) Fatal(eventType, message string, details map[string]interface{}) {
	l.log(LevelError, eventType, message, details)
	os.Exit(1)
}

func Info(eventType, message string, details map[string]interface{}) {
	GetLogger().Info(eventType, message, details)
}
func Warn(eventType, message string, details map[string]interface{}) {
	GetLogger().Warn(eventType, message, details)
}
func Error(eventType, message string, details map[string]interface{}) {
	GetLogger().Error(eventType, message, details)
}
func Security(eventType, message string, details map[string]interface{}) {
	GetLogger().Security(eventType, message, details)
}
func Fatal(eventType, message string, details map[string]interface{}) {
	GetLogger().Fatal(eventType, message, details)
}

func Fields(kv ...interface{}) map[string]interface{} {
	details := make(map[string]interface{})
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			continue
		}
		details[key] = kv[i+1]
	}
	return details
}

func (l *Logger) computeHMAC(entry LogEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", entry.Timestamp, entry.Level, entry.Service, entry.EventType, entry.Message)
	mac := hmac.New(sha256.New, l.hmacKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func (l *Logger) sanitizeDetails(details map[string]interface{}) map[string]interface{} {
	if details == nil {
		return nil
	}
	sanitized := make(map[string]interface{})
	for k, v := range details {
		sanitized[k] = l.sanitizeValue(k, v)
	}
	return sanitized
}

func (l *Logger) sanitizeValue(key string, value interface{}) interface{} {
	keyLower := strings.ToLower(key)
	if sensitiveFields[keyLower] {
		return "[REDACTED]"
	}
	switch v := value.(type) {
	case string:
		return l.sanitizeString(v)
	case map[string]interface{}:
		return l.sanitizeDetails(v)
	default:
		return v
	}
}

func (l *Logger) sanitizeString(s string) string {
	s = emailRegex.ReplaceAllStringFunc(s, maskEmail)
	if l.config.Environment == "production" {
		s = removeStackTraces(s)
	}
	return s
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[REDACTED_EMAIL]"
	}
	local := parts[0]
	if len(local) <= 2 {
		return "**@" + parts[1]
	}
	return local[:2] + "***@" + parts[1]
}

func removeStackTraces(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	lines := strings.Split(s, "\n")
	var filtered []string
	for _, line := range lines {
		isStackTrace := false
		for _, pattern := range stackTraceIndicators {
			if strings.Contains(line, pattern) {
				isStackTrace = true
				break
			}
		}
		if !isStackTrace {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}
