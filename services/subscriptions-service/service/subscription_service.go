package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/annazecevic/subscriptions-service/domain"
	"github.com/annazecevic/subscriptions-service/logger"
	"github.com/annazecevic/subscriptions-service/messaging"
	"github.com/annazecevic/subscriptions-service/repository"
	"github.com/annazecevic/subscriptions-service/resilience"
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
	publisher         *messaging.Publisher
	contentServiceURL string
	httpClient *http.Client
	contentCB *resilience.CircuitBreaker
	retryCfg resilience.RetryConfig
}

func NewSubscriptionService(repo repository.SubscriptionRepository, publisher *messaging.Publisher, contentServiceURL string) SubscriptionService {
	return &subscriptionService{
		repo:              repo,
		publisher:         publisher,
		contentServiceURL: contentServiceURL,
		httpClient:        resilience.NewHTTPClient(),
		contentCB:         resilience.NewCircuitBreaker("content-service", 5, 3, 30*time.Second),
		retryCfg:          resilience.DefaultRetryConfig(),
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

	if s.publisher != nil {
		go func() {
			if err := s.publisher.PublishSubscriptionCreated(messaging.SubscriptionCreatedEvent{
				UserID:   userID,
				Type:     string(subType),
				TargetID: targetID,
				Name:     name,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish subscription created event", logger.Fields("error", err.Error()))
			}
		}()
	}

	return subscription, nil
}

func (s *subscriptionService) Unsubscribe(userID string, subscriptionID string) error {
	sub, _ := s.repo.GetByID(userID, subscriptionID)

	err := s.repo.Delete(userID, subscriptionID)
	if err != nil {
		return err
	}

	logger.Info(logger.EventGeneral, "User unsubscribed from content", logger.Fields(
		"user_id", userID,
		"subscription_id", subscriptionID,
	))

	if s.publisher != nil && sub != nil {
		go func() {
			if err := s.publisher.PublishSubscriptionDeleted(messaging.SubscriptionDeletedEvent{
				UserID:   userID,
				Type:     string(sub.Type),
				TargetID: sub.TargetID,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish subscription deleted event", logger.Fields("error", err.Error()))
			}
		}()
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "Content service unavailable, allowing subscription (fallback)", logger.Fields(
			"target_id", targetID,
			"error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(s.contentCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		if authToken != "" {
			req.Header.Set("Authorization", authToken)
		}
		return s.httpClient.Do(req)
	}, fallback)

	if err != nil {
		return "", nil
	}
	if resp == nil {
		return "", nil
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
