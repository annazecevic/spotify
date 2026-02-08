package repository

import (
	"fmt"
	"time"

	"github.com/annazecevic/notifications-service/domain"
	"github.com/annazecevic/notifications-service/logger"
	"github.com/gocql/gocql"
)

type NotificationRepository interface {
	GetUserNotifications(userID string) ([]domain.Notification, error)
	GetAllNotifications() ([]domain.Notification, error)
	CreateNotification(notification *domain.Notification) error
}

type notificationRepository struct {
	session *gocql.Session
}

func NewNotificationRepository(session *gocql.Session) NotificationRepository {
	return &notificationRepository{
		session: session,
	}
}

func (r *notificationRepository) GetUserNotifications(userID string) ([]domain.Notification, error) {
	query := `SELECT id, user_id, type, message, title, created_at, read, 
	          artist_id, genre_id, album_id, track_id 
	          FROM notifications 
	          WHERE user_id = ? 
	          ORDER BY created_at DESC`

	iter := r.session.Query(query, userID).Iter()
	defer iter.Close()

	var notifications []domain.Notification
	var n domain.Notification

	for iter.Scan(&n.ID, &n.UserID, &n.Type, &n.Message, &n.Title, &n.CreatedAt,
		&n.Read, &n.ArtistID, &n.GenreID, &n.AlbumID, &n.TrackID) {
		notifications = append(notifications, n)
		n = domain.Notification{}
	}

	if err := iter.Close(); err != nil {
		logger.Error(logger.EventDBError, "Error fetching user notifications", logger.Fields("user_id", userID, "error", err.Error()))
		return nil, fmt.Errorf("failed to fetch notifications: %w", err)
	}

	return notifications, nil
}

func (r *notificationRepository) GetAllNotifications() ([]domain.Notification, error) {
	query := `SELECT id, user_id, type, message, title, created_at, read, 
	          artist_id, genre_id, album_id, track_id 
	          FROM notifications`

	iter := r.session.Query(query).Iter()
	defer iter.Close()

	var notifications []domain.Notification
	var n domain.Notification

	for iter.Scan(&n.ID, &n.UserID, &n.Type, &n.Message, &n.Title, &n.CreatedAt,
		&n.Read, &n.ArtistID, &n.GenreID, &n.AlbumID, &n.TrackID) {
		notifications = append(notifications, n)
		n = domain.Notification{}
	}

	if err := iter.Close(); err != nil {
		logger.Error(logger.EventDBError, "Error fetching all notifications", logger.Fields("error", err.Error()))
		return nil, fmt.Errorf("failed to fetch notifications: %w", err)
	}

	return notifications, nil
}

func (r *notificationRepository) CreateNotification(notification *domain.Notification) error {
	if notification.ID == (gocql.UUID{}) {
		notification.ID = gocql.TimeUUID()
	}
	if notification.CreatedAt.IsZero() {
		notification.CreatedAt = time.Now()
	}

	query := `INSERT INTO notifications (id, user_id, type, message, title, created_at, read, 
	          artist_id, genre_id, album_id, track_id) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	err := r.session.Query(query,
		notification.ID,
		notification.UserID,
		notification.Type,
		notification.Message,
		notification.Title,
		notification.CreatedAt,
		notification.Read,
		notification.ArtistID,
		notification.GenreID,
		notification.AlbumID,
		notification.TrackID,
	).Exec()

	if err != nil {
		logger.Error(logger.EventDBError, "Error creating notification", logger.Fields("error", err.Error()))
		return fmt.Errorf("failed to create notification: %w", err)
	}

	return nil
}
