package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/annazecevic/subscriptions-service/domain"
	"github.com/annazecevic/subscriptions-service/logger"
	"github.com/annazecevic/subscriptions-service/repository"
	"github.com/google/uuid"
)

type ContentInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SubscriptionService interface {
	Subscribe(userID string, subType domain.SubscriptionType, targetID string, authToken string) (*domain.Subscription, error)
	Unsubscribe(userID string, subscriptionID string) error
	GetUserSubscriptions(userID string) ([]domain.Subscription, error)
	GetUserSubscriptionsByType(userID string, subType domain.SubscriptionType) ([]domain.Subscription, error)
	CheckSubscription(userID string, targetID string) (bool, error)
	GetSubscribersByTarget(targetID string, subType domain.SubscriptionType) ([]domain.Subscription, error)
}

type subscriptionService struct {
	repo              repository.SubscriptionRepository
	contentServiceURL string
}

func NewSubscriptionService(repo repository.SubscriptionRepository, contentServiceURL string) SubscriptionService {
	return &subscriptionService{
		repo:              repo,
		contentServiceURL: contentServiceURL,
	}
}

func (s *subscriptionService) Subscribe(userID string, subType domain.SubscriptionType, targetID string, authToken string) (*domain.Subscription, error) {
	existing, err := s.repo.GetByUserIDAndTarget(userID, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing subscription: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("already subscribed to this content")
	}

	name, err := s.validateAndGetName(subType, targetID, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate target: %w", err)
	}

	subscription := &domain.Subscription{
		ID:        uuid.New().String(),
		UserID:    userID,
		Type:      subType,
		TargetID:  targetID,
		Name:      name,
		CreatedAt: time.Now(),
	}

	if err := s.repo.Create(subscription); err != nil {
		return nil, err
	}

	logger.Info(logger.EventGeneral, "User subscribed to content", logger.Fields(
		"user_id", userID,
		"type", string(subType),
		"target_id", targetID,
		"name", name,
	))

	return subscription, nil
}

func (s *subscriptionService) Unsubscribe(userID string, subscriptionID string) error {
	err := s.repo.Delete(userID, subscriptionID)
	if err != nil {
		return err
	}

	logger.Info(logger.EventGeneral, "User unsubscribed from content", logger.Fields(
		"user_id", userID,
		"subscription_id", subscriptionID,
	))

	return nil
}

func (s *subscriptionService) GetUserSubscriptions(userID string) ([]domain.Subscription, error) {
	return s.repo.GetByUserID(userID)
}

func (s *subscriptionService) GetUserSubscriptionsByType(userID string, subType domain.SubscriptionType) ([]domain.Subscription, error) {
	return s.repo.GetByUserIDAndType(userID, subType)
}

func (s *subscriptionService) CheckSubscription(userID string, targetID string) (bool, error) {
	sub, err := s.repo.GetByUserIDAndTarget(userID, targetID)
	if err != nil {
		return false, err
	}
	return sub != nil, nil
}

func (s *subscriptionService) GetSubscribersByTarget(targetID string, subType domain.SubscriptionType) ([]domain.Subscription, error) {
	return s.repo.GetSubscribersByTarget(targetID, subType)
}

func (s *subscriptionService) validateAndGetName(subType domain.SubscriptionType, targetID string, authToken string) (string, error) {
	var url string
	switch subType {
	case domain.SubscriptionTypeArtist:
		url = fmt.Sprintf("%s/content/artists/%s", s.contentServiceURL, targetID)
	case domain.SubscriptionTypeGenre:
		url = fmt.Sprintf("%s/content/genres/%s", s.contentServiceURL, targetID)
	default:
		return "", fmt.Errorf("invalid subscription type: %s", subType)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if authToken != "" {
		req.Header.Set("Authorization", authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to reach content service", logger.Fields(
			"url", url,
			"error", err.Error(),
		))
		return "", fmt.Errorf("content service unavailable, cannot verify target exists")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("target content not found")
	}

	if resp.StatusCode != http.StatusOK {
		logger.Warn(logger.EventGeneral, "Content service returned non-OK status", logger.Fields(
			"url", url,
			"status", resp.StatusCode,
		))
		return "", nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil
	}

	var info ContentInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", nil
	}

	return info.Name, nil
}
