package resilience

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/annazecevic/recommendation-service/logger"
)

type CircuitState int

const (
	StateClosed   CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
	timeout          time.Duration
	lastFailureTime  time.Time
	name             string
}

func NewCircuitBreaker(name string, failureThreshold int, successThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
		name:             name,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = StateHalfOpen
			cb.successCount = 0
			logger.Info(logger.EventGeneral, "Circuit breaker transitioning to HALF_OPEN", logger.Fields("name", cb.name))
			return true
		}
		return false
	case StateHalfOpen:
		return true
	}
	return false
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.state = StateClosed
			cb.failureCount = 0
			cb.successCount = 0
			logger.Info(logger.EventGeneral, "Circuit breaker CLOSED (recovered)", logger.Fields("name", cb.name))
		}
	case StateClosed:
		cb.failureCount = 0
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			cb.state = StateOpen
			logger.Warn(logger.EventGeneral, "Circuit breaker OPEN (tripped)", logger.Fields("name", cb.name, "failures", cb.failureCount))
		}
	case StateHalfOpen:
		cb.state = StateOpen
		cb.failureCount = 0
		logger.Warn(logger.EventGeneral, "Circuit breaker back to OPEN from HALF_OPEN", logger.Fields("name", cb.name))
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

type RetryConfig struct {
	MaxRetries      int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	RetryableStatus []int
}

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		BaseDelay:       500 * time.Millisecond,
		MaxDelay:        5 * time.Second,
		RetryableStatus: []int{http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests},
	}
}

func isRetryableStatus(statusCode int, retryable []int) bool {
	for _, s := range retryable {
		if s == statusCode {
			return true
		}
	}
	return false
}

func Execute(
	cb *CircuitBreaker,
	retryCfg RetryConfig,
	doRequest func() (*http.Response, error),
	fallback func(error) (*http.Response, error),
) (*http.Response, error) {
	if !cb.Allow() {
		logger.Warn(logger.EventGeneral, "Circuit breaker is OPEN, using fallback", logger.Fields("circuit", cb.name, "state", cb.State().String()))
		if fallback != nil {
			return fallback(fmt.Errorf("circuit breaker open for %s", cb.name))
		}
		return nil, fmt.Errorf("circuit breaker open for %s", cb.name)
	}

	var lastErr error
	var resp *http.Response

	for attempt := 0; attempt <= retryCfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(retryCfg.BaseDelay) * math.Pow(2, float64(attempt-1)))
			if delay > retryCfg.MaxDelay {
				delay = retryCfg.MaxDelay
			}
			logger.Warn(logger.EventGeneral, "Retrying request", logger.Fields(
				"circuit", cb.name, "attempt", fmt.Sprintf("%d/%d", attempt, retryCfg.MaxRetries), "delay_ms", delay.Milliseconds(),
			))
			time.Sleep(delay)
		}

		resp, lastErr = doRequest()
		if lastErr != nil {
			cb.RecordFailure()
			continue
		}

		if isRetryableStatus(resp.StatusCode, retryCfg.RetryableStatus) {
			resp.Body.Close()
			lastErr = fmt.Errorf("received retryable status %d", resp.StatusCode)
			cb.RecordFailure()
			continue
		}

		cb.RecordSuccess()
		return resp, nil
	}

	cb.RecordFailure()
	logger.Error(logger.EventGeneral, "All retries exhausted, using fallback", logger.Fields("circuit", cb.name, "error", lastErr.Error()))
	if fallback != nil {
		return fallback(lastErr)
	}
	return nil, fmt.Errorf("service %s unavailable after %d retries: %w", cb.name, retryCfg.MaxRetries, lastErr)
}
