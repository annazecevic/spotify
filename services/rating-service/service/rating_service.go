package service

import (
	"fmt"
	"net/http"
	"time"

	"github.com/annazecevic/rating-service/domain"
	"github.com/annazecevic/rating-service/logger"
	"github.com/annazecevic/rating-service/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RatingService interface {
	CreateOrUpdateRating(c *gin.Context, trackID string, value int) (*domain.Rating, error)
	DeleteRating(c *gin.Context, trackID string) error
	GetAverageRating(trackID string) (float64, error)
	GetUserRating(c *gin.Context, trackID string) (*domain.Rating, error)
	GetAllRatingsForTrack(trackID string) ([]*domain.Rating, error)
}

type ratingService struct {
	repo              repository.RatingRepository
	contentServiceURL string
	userServiceURL    string
}

func NewRatingService(repo repository.RatingRepository, contentServiceURL string, userServiceURL string) RatingService {
	return &ratingService{
		repo:              repo,
		contentServiceURL: contentServiceURL,
		userServiceURL:    userServiceURL,
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

	if err := s.validateTrackExists(trackID); err != nil {
		return nil, err
	}

	if err := s.validateUserExists(userID); err != nil {
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

	return nil
}

func (s *ratingService) GetAverageRating(trackID string) (float64, error) {
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

func (s *ratingService) validateTrackExists(trackID string) error {

	url := fmt.Sprintf("%s/content/tracks/%s", s.contentServiceURL, trackID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("content service unavailable")
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

func (s *ratingService) validateUserExists(userID string) error {

	url := fmt.Sprintf("%s/users/%s", s.userServiceURL, userID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("user service unavailable")
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
