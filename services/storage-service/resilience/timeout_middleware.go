package resilience

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"storage-service/logger"
)

func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		finished := make(chan struct{}, 1)
		go func() {
			c.Next()
			finished <- struct{}{}
		}()

		select {
		case <-finished:
		case <-ctx.Done():
			logger.Warn(logger.EventGeneral, "Request timeout exceeded", logger.Fields(
				"path", c.Request.URL.Path, "method", c.Request.Method, "timeout_ms", timeout.Milliseconds(),
			))
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "request timeout exceeded"})
		}
	}
}
