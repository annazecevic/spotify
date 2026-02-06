package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a simple in-memory rate limiter (2.17 - DoS protection)
type RateLimiter struct {
	requests map[string]*userRequests
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

type userRequests struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*userRequests),
		limit:    limit,
		window:   window,
	}

	go rl.cleanup()

	return rl
}

// Middleware returns a Gin middleware function (2.17)
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.ClientIP()

		// For authenticated requests, use user ID
		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(string); ok && uid != "" {
				identifier = "user:" + uid
			}
		}

		if !rl.allow(identifier) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate limit exceeded",
				"message": "too many requests, please try again later",
			})
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) allow(identifier string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	req, exists := rl.requests[identifier]

	if !exists || now.After(req.resetTime) {
		rl.requests[identifier] = &userRequests{
			count:     1,
			resetTime: now.Add(rl.window),
		}
		return true
	}

	if req.count >= rl.limit {
		return false
	}

	req.count++
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, req := range rl.requests {
			if now.After(req.resetTime) {
				delete(rl.requests, key)
			}
		}
		rl.mu.Unlock()
	}
}

