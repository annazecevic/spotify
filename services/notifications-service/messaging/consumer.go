package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/annazecevic/notifications-service/domain"
	"github.com/annazecevic/notifications-service/logger"
	"github.com/annazecevic/notifications-service/resilience"
	"github.com/annazecevic/notifications-service/service"
	"github.com/nats-io/nats.go"
)

type Consumer struct {
	conn                    *nats.Conn
	notificationService     service.NotificationService
	subscriptionsServiceURL string
	httpClient *http.Client
	subscriptionsCB *resilience.CircuitBreaker
	retryCfg resilience.RetryConfig
}

func NewConsumer(natsURL string, notifService service.NotificationService, subscriptionsURL string) (*Consumer, error) {
	var conn *nats.Conn
	var err error

	for i := 0; i < 10; i++ {
		conn, err = nats.Connect(natsURL,
			nats.RetryOnFailedConnect(true),
			nats.MaxReconnects(60),
			nats.ReconnectWait(2*time.Second),
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				if err != nil {
					logger.Warn(logger.EventGeneral, "NATS disconnected", logger.Fields("error", err.Error()))
				}
			}),
			nats.ReconnectHandler(func(_ *nats.Conn) {
				logger.Info(logger.EventGeneral, "NATS reconnected", nil)
			}),
		)
		if err == nil {
			break
		}
		logger.Warn(logger.EventGeneral, "Failed to connect to NATS, retrying...", logger.Fields(
			"attempt", fmt.Sprintf("%d/10", i+1),
			"error", err.Error(),
		))
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS after retries: %w", err)
	}

	logger.Info(logger.EventGeneral, "NATS consumer connected successfully", logger.Fields("url", natsURL))

	return &Consumer{
		conn:                    conn,
		notificationService:     notifService,
		subscriptionsServiceURL: subscriptionsURL,
		httpClient:              resilience.NewHTTPClient(),
		subscriptionsCB:         resilience.NewCircuitBreaker("subscriptions-service", 5, 3, 30*time.Second),
		retryCfg:                resilience.DefaultRetryConfig(),
	}, nil
}

func (c *Consumer) Start() error {
	if _, err := c.conn.Subscribe(SubjectAlbumCreated, c.handleAlbumCreated); err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", SubjectAlbumCreated, err)
	}
	logger.Info(logger.EventGeneral, "Subscribed to NATS subject", logger.Fields("subject", SubjectAlbumCreated))

	if _, err := c.conn.Subscribe(SubjectTrackCreated, c.handleTrackCreated); err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", SubjectTrackCreated, err)
	}
	logger.Info(logger.EventGeneral, "Subscribed to NATS subject", logger.Fields("subject", SubjectTrackCreated))

	if _, err := c.conn.Subscribe(SubjectArtistCreated, c.handleArtistCreated); err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", SubjectArtistCreated, err)
	}
	logger.Info(logger.EventGeneral, "Subscribed to NATS subject", logger.Fields("subject", SubjectArtistCreated))

	return nil
}

func (c *Consumer) handleAlbumCreated(msg *nats.Msg) {
	var event AlbumCreatedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal album created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received album created event", logger.Fields(
		"album_id", event.AlbumID,
		"title", event.Title,
		"artist_count", len(event.ArtistIDs),
	))

	notifiedUsers := make(map[string]bool)
	for _, artistID := range event.ArtistIDs {
		subscribers, err := c.getSubscribers(artistID, "ARTIST")
		if err != nil {
			logger.Error(logger.EventGeneral, "Failed to get subscribers for artist", logger.Fields(
				"artist_id", artistID,
				"error", err.Error(),
			))
			continue
		}

		for _, sub := range subscribers {
			if notifiedUsers[sub.UserID] {
				continue
			}
			notifiedUsers[sub.UserID] = true

			notification := &domain.Notification{
				UserID:   sub.UserID,
				Type:     domain.NotificationTypeNewAlbum,
				Title:    "Novi album",
				Message:  fmt.Sprintf("Novi album \"%s\" je dodat od umetnika na čiji sadržaj ste pretplaćeni.", event.Title),
				ArtistID: artistID,
				AlbumID:  event.AlbumID,
			}

			if err := c.notificationService.CreateNotification(notification); err != nil {
				logger.Error(logger.EventGeneral, "Failed to create album notification", logger.Fields(
					"user_id", sub.UserID,
					"album_id", event.AlbumID,
					"error", err.Error(),
				))
			} else {
				logger.Info(logger.EventGeneral, "Album notification created", logger.Fields(
					"user_id", sub.UserID,
					"album_id", event.AlbumID,
				))
			}
		}
	}
}

func (c *Consumer) handleTrackCreated(msg *nats.Msg) {
	var event TrackCreatedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal track created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received track created event", logger.Fields(
		"track_id", event.TrackID,
		"title", event.Title,
		"artist_count", len(event.ArtistIDs),
	))

	notifiedUsers := make(map[string]bool)
	for _, artistID := range event.ArtistIDs {
		subscribers, err := c.getSubscribers(artistID, "ARTIST")
		if err != nil {
			logger.Error(logger.EventGeneral, "Failed to get subscribers for artist", logger.Fields(
				"artist_id", artistID,
				"error", err.Error(),
			))
			continue
		}

		for _, sub := range subscribers {
			if notifiedUsers[sub.UserID] {
				continue
			}
			notifiedUsers[sub.UserID] = true

			notification := &domain.Notification{
				UserID:   sub.UserID,
				Type:     domain.NotificationTypeNewTrack,
				Title:    "Nova pesma",
				Message:  fmt.Sprintf("Nova pesma \"%s\" je dodata od umetnika na čiji sadržaj ste pretplaćeni.", event.Title),
				ArtistID: artistID,
				TrackID:  event.TrackID,
			}

			if err := c.notificationService.CreateNotification(notification); err != nil {
				logger.Error(logger.EventGeneral, "Failed to create track notification", logger.Fields(
					"user_id", sub.UserID,
					"track_id", event.TrackID,
					"error", err.Error(),
				))
			} else {
				logger.Info(logger.EventGeneral, "Track notification created", logger.Fields(
					"user_id", sub.UserID,
					"track_id", event.TrackID,
				))
			}
		}
	}
}

func (c *Consumer) handleArtistCreated(msg *nats.Msg) {
	var event ArtistCreatedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal artist created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received artist created event", logger.Fields(
		"artist_id", event.ArtistID,
		"name", event.Name,
		"genre_count", len(event.GenreIDs),
	))

	notifiedUsers := make(map[string]bool)
	for _, genreID := range event.GenreIDs {
		subscribers, err := c.getSubscribers(genreID, "GENRE")
		if err != nil {
			logger.Error(logger.EventGeneral, "Failed to get subscribers for genre", logger.Fields(
				"genre_id", genreID,
				"error", err.Error(),
			))
			continue
		}

		for _, sub := range subscribers {
			if notifiedUsers[sub.UserID] {
				continue
			}
			notifiedUsers[sub.UserID] = true

			notification := &domain.Notification{
				UserID:   sub.UserID,
				Type:     domain.NotificationTypeNewArtist,
				Title:    "Novi umetnik",
				Message:  fmt.Sprintf("Novi umetnik \"%s\" je dodat u žanr na koji ste pretplaćeni.", event.Name),
				ArtistID: event.ArtistID,
				GenreID:  genreID,
			}

			if err := c.notificationService.CreateNotification(notification); err != nil {
				logger.Error(logger.EventGeneral, "Failed to create artist notification", logger.Fields(
					"user_id", sub.UserID,
					"artist_id", event.ArtistID,
					"error", err.Error(),
				))
			} else {
				logger.Info(logger.EventGeneral, "Artist notification created", logger.Fields(
					"user_id", sub.UserID,
					"artist_id", event.ArtistID,
				))
			}
		}
	}
}

func (c *Consumer) getSubscribers(targetID string, subType string) ([]Subscriber, error) {
	url := fmt.Sprintf("%s/api/v1/internal/subscriptions/subscribers/%s?type=%s", c.subscriptionsServiceURL, targetID, subType)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "Subscriptions service unavailable, returning empty subscribers (fallback)", logger.Fields(
			"target_id", targetID, "type", subType, "error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(c.subscriptionsCB, c.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		return c.httpClient.Do(req)
	}, fallback)

	if err != nil || resp == nil {
		return []Subscriber{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("subscriptions service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []struct {
			UserID string `json:"user_id"`
		} `json:"data"`
		Count int `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode subscribers response: %w", err)
	}

	subscribers := make([]Subscriber, 0, len(result.Data))
	for _, d := range result.Data {
		subscribers = append(subscribers, Subscriber{UserID: d.UserID})
	}

	logger.Info(logger.EventGeneral, "Fetched subscribers", logger.Fields(
		"target_id", targetID,
		"type", subType,
		"count", len(subscribers),
	))

	return subscribers, nil
}

func (c *Consumer) Close() {
	if c.conn != nil {
		c.conn.Drain()
	}
}
