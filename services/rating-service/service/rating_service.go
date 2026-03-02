package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/annazecevic/rating-service/domain"
	"github.com/annazecevic/rating-service/logger"
	"github.com/annazecevic/rating-service/messaging"
	"github.com/annazecevic/rating-service/repository"
	"github.com/annazecevic/rating-service/resilience"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RatingService interface {
	CreateOrUpdateRating(c *gin.Context, trackID string, value int) (*domain.Rating, error)
	DeleteRating(c *gin.Context, trackID string) error
	GetAverageRating(trackID string) (float64, int64, error)
	GetUserRating(c *gin.Context, trackID string) (*domain.Rating, error)
	GetAllRatingsForTrack(trackID string) ([]*domain.Rating, error)
}

type ratingService struct {
	repo              repository.RatingRepository
	publisher         *messaging.Publisher
	contentServiceURL string
	userServiceURL    string
	httpClient *http.Client
	contentCB *resilience.CircuitBreaker
	userCB    *resilience.CircuitBreaker
	retryCfg resilience.RetryConfig
}

func NewRatingService(repo repository.RatingRepository, publisher *messaging.Publisher, contentServiceURL string, userServiceURL string) RatingService {
	return &ratingService{
		repo:              repo,
		publisher:         publisher,
		contentServiceURL: contentServiceURL,
		userServiceURL:    userServiceURL,
		httpClient:        resilience.NewHTTPClient(),
		contentCB:         resilience.NewCircuitBreaker("content-service", 5, 3, 30*time.Second),
		userCB:            resilience.NewCircuitBreaker("user-service", 5, 3, 30*time.Second),
		retryCfg:          resilience.DefaultRetryConfig(),
	}
}

func (s *ratingService) CreateOrUpdateRating(c *gin.Context, trackID string, value int) (*domain.Rating, error) {

	userID := c.GetString("user_id")
	if userID == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	if trackID == "" {
		return nil, fmt.Errorf("trackID is required")
	}

	if value < 1 || value > 5 {
		return nil, fmt.Errorf("rating must be between 1 and 5")
	}

	if err := s.validateTrackExists(c, trackID); err != nil {
		return nil, err
	}

	existing, err := s.repo.GetByUserIDAndTrackID(userID, trackID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing rating: %w", err)
	}

	now := time.Now()

	if existing != nil {
		existing.Value = value
		existing.UpdatedAt = now

		if err := s.repo.UpdateRating(existing); err != nil {
			return nil, err
		}

		logger.Info(logger.EventGeneral, "Rating updated", logger.Fields(
			"user_id", userID,
			"track_id", trackID,
			"value", value,
		))

		if s.publisher != nil {
			go func() {
				if err := s.publisher.PublishRatingUpdated(messaging.RatingEvent{
					UserID: userID, TrackID: trackID, Value: value,
				}); err != nil {
					logger.Error(logger.EventGeneral, "Failed to publish rating updated event", logger.Fields("error", err.Error()))
				}
			}()
		}

		return existing, nil
	}

	rating := &domain.Rating{
		ID:        uuid.New().String(),
		UserID:    userID,
		TrackID:   trackID,
		Value:     value,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.repo.CreateRating(rating); err != nil {
		return nil, err
	}

	logger.Info(logger.EventGeneral, "Rating created", logger.Fields(
		"user_id", userID,
		"track_id", trackID,
		"value", value,
	))

	if s.publisher != nil {
		go func() {
			if err := s.publisher.PublishRatingCreated(messaging.RatingEvent{
				UserID: userID, TrackID: trackID, Value: value,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish rating created event", logger.Fields("error", err.Error()))
			}
		}()
	}

	return rating, nil
}

func (s *ratingService) DeleteRating(c *gin.Context, trackID string) error {

	userID := c.GetString("user_id")
	if userID == "" {
		return fmt.Errorf("unauthorized")
	}

	if trackID == "" {
		return fmt.Errorf("trackID is required")
	}

	err := s.repo.DeleteRating(userID, trackID)
	if err != nil {
		return err
	}

	logger.Info(logger.EventGeneral, "Rating deleted", logger.Fields(
		"user_id", userID,
		"track_id", trackID,
	))

	if s.publisher != nil {
		go func() {
			if err := s.publisher.PublishRatingDeleted(messaging.RatingDeletedEvent{
				UserID: userID, TrackID: trackID,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish rating deleted event", logger.Fields("error", err.Error()))
			}
		}()
	}

	return nil
}

func (s *ratingService) GetAverageRating(trackID string) (float64, int64, error) {
	return s.repo.GetAverageByTrackID(trackID)
}

func (s *ratingService) GetUserRating(c *gin.Context, trackID string) (*domain.Rating, error) {
	userID := c.GetString("user_id")
	if userID == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	return s.repo.GetByUserIDAndTrackID(userID, trackID)
}

func (s *ratingService) GetAllRatingsForTrack(trackID string) ([]*domain.Rating, error) {
	return s.repo.GetByTrackID(trackID)
}

func (s *ratingService) validateTrackExists(c *gin.Context, trackID string) error {
	url := fmt.Sprintf("%s/content/tracks/%s", s.contentServiceURL, trackID)

	ctx := c.Request.Context()
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "Content service unavailable, allowing rating (fallback)", logger.Fields(
			"track_id", trackID,
			"error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(s.contentCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		return s.httpClient.Do(req)
	}, fallback)

	if err != nil {
		return nil
	}
	if resp == nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("track not found")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("content service error")
	}

	return nil
}

func (s *ratingService) validateUserExists(c *gin.Context, userID string) error {
	url := fmt.Sprintf("%s/users/%s", s.userServiceURL, userID)

	ctx := c.Request.Context()
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "User service unavailable, allowing operation (fallback)", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(s.userCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		return s.httpClient.Do(req)
	}, fallback)

	if err != nil {
		return nil
	}
	if resp == nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user not found")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("user service error")
	}

	return nil
}
