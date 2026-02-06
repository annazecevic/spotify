package service

import (
	"github.com/annazecevic/notifications-service/domain"
	"github.com/annazecevic/notifications-service/repository"
)

type NotificationService interface {
	GetUserNotifications(userID string) ([]domain.Notification, error)
	GetAllNotifications() ([]domain.Notification, error)
	CreateNotification(notification *domain.Notification) error
}

type notificationService struct {
	repo repository.NotificationRepository
}

func NewNotificationService(repo repository.NotificationRepository) NotificationService {
	return &notificationService{
		repo: repo,
	}
}

func (s *notificationService) GetUserNotifications(userID string) ([]domain.Notification, error) {
	return s.repo.GetUserNotifications(userID)
}

func (s *notificationService) GetAllNotifications() ([]domain.Notification, error) {
	return s.repo.GetAllNotifications()
}

func (s *notificationService) CreateNotification(notification *domain.Notification) error {
	return s.repo.CreateNotification(notification)
}
