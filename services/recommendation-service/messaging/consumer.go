package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/annazecevic/recommendation-service/logger"
	"github.com/annazecevic/recommendation-service/repository"
	"github.com/nats-io/nats.go"
)

type Consumer struct {
	conn *nats.Conn
	repo repository.RecommendationRepository
}

func NewConsumer(natsURL string, repo repository.RecommendationRepository) (*Consumer, error) {
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
		conn: conn,
		repo: repo,
	}, nil
}

func (c *Consumer) Start() error {
	subjects := map[string]nats.MsgHandler{
		SubjectGenreCreated:        c.handleGenreCreated,
		SubjectArtistCreated:       c.handleArtistCreated,
		SubjectTrackCreated:        c.handleTrackCreated,
		SubjectRatingCreated:       c.handleRatingCreated,
		SubjectRatingUpdated:       c.handleRatingUpdated,
		SubjectRatingDeleted:       c.handleRatingDeleted,
		SubjectSubscriptionCreated: c.handleSubscriptionCreated,
		SubjectSubscriptionDeleted: c.handleSubscriptionDeleted,
	}

	for subject, handler := range subjects {
		if _, err := c.conn.Subscribe(subject, handler); err != nil {
			return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
		}
		logger.Info(logger.EventGeneral, "Subscribed to NATS subject", logger.Fields("subject", subject))
	}

	return nil
}

func (c *Consumer) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}


func (c *Consumer) handleGenreCreated(msg *nats.Msg) {
	var event GenreCreatedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal genre created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received genre created event", logger.Fields(
		"genre_id", event.GenreID,
		"name", event.Name,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.SyncGenre(ctx, event.GenreID, event.Name); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync genre from event", logger.Fields(
			"genre_id", event.GenreID,
			"error", err.Error(),
		))
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
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.SyncArtist(ctx, event.ArtistID, event.Name); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync artist from event", logger.Fields(
			"artist_id", event.ArtistID,
			"error", err.Error(),
		))
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
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trackData := repository.TrackData{
		ID:        event.TrackID,
		Title:     event.Title,
		Duration:  event.Duration,
		Genre:     event.Genre,
		AlbumID:   event.AlbumID,
		ArtistIDs: event.ArtistIDs,
	}

	if err := c.repo.SyncTrack(ctx, trackData); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync track from event", logger.Fields(
			"track_id", event.TrackID,
			"error", err.Error(),
		))
		return
	}

	if event.Genre != "" {
		if err := c.repo.SyncTrackGenre(ctx, event.TrackID, event.Genre); err != nil {
			logger.Warn(logger.EventGeneral, "Failed to sync track-genre from event", logger.Fields(
				"track_id", event.TrackID,
				"genre", event.Genre,
				"error", err.Error(),
			))
		}
	}

	for _, artistID := range event.ArtistIDs {
		if err := c.repo.SyncTrackArtist(ctx, event.TrackID, artistID); err != nil {
			logger.Warn(logger.EventGeneral, "Failed to sync track-artist from event", logger.Fields(
				"track_id", event.TrackID,
				"artist_id", artistID,
				"error", err.Error(),
			))
		}
	}
}


func (c *Consumer) handleRatingCreated(msg *nats.Msg) {
	var event RatingEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal rating created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received rating created event", logger.Fields(
		"user_id", event.UserID,
		"track_id", event.TrackID,
		"value", event.Value,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.SyncUser(ctx, event.UserID); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to sync user from rating event", logger.Fields("error", err.Error()))
	}

	if err := c.repo.SyncRating(ctx, event.UserID, event.TrackID, event.Value); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync rating from event", logger.Fields(
			"user_id", event.UserID,
			"track_id", event.TrackID,
			"error", err.Error(),
		))
	}
}

func (c *Consumer) handleRatingUpdated(msg *nats.Msg) {
	var event RatingEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal rating updated event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received rating updated event", logger.Fields(
		"user_id", event.UserID,
		"track_id", event.TrackID,
		"value", event.Value,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.SyncRating(ctx, event.UserID, event.TrackID, event.Value); err != nil {
		logger.Error(logger.EventGeneral, "Failed to update rating from event", logger.Fields(
			"user_id", event.UserID,
			"track_id", event.TrackID,
			"error", err.Error(),
		))
	}
}

func (c *Consumer) handleRatingDeleted(msg *nats.Msg) {
	var event RatingDeletedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal rating deleted event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received rating deleted event", logger.Fields(
		"user_id", event.UserID,
		"track_id", event.TrackID,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.RemoveRating(ctx, event.UserID, event.TrackID); err != nil {
		logger.Error(logger.EventGeneral, "Failed to remove rating from event", logger.Fields(
			"user_id", event.UserID,
			"track_id", event.TrackID,
			"error", err.Error(),
		))
	}
}


func (c *Consumer) handleSubscriptionCreated(msg *nats.Msg) {
	var event SubscriptionCreatedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal subscription created event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received subscription created event", logger.Fields(
		"user_id", event.UserID,
		"type", event.Type,
		"target_id", event.TargetID,
	))

	if event.Type != "GENRE" {
		logger.Info(logger.EventGeneral, "Ignoring non-genre subscription event", logger.Fields("type", event.Type))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.SyncUser(ctx, event.UserID); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to sync user from subscription event", logger.Fields("error", err.Error()))
	}

	if err := c.repo.SyncSubscription(ctx, event.UserID, event.TargetID); err != nil {
		logger.Error(logger.EventGeneral, "Failed to sync subscription from event", logger.Fields(
			"user_id", event.UserID,
			"target_id", event.TargetID,
			"error", err.Error(),
		))
	}
}

func (c *Consumer) handleSubscriptionDeleted(msg *nats.Msg) {
	var event SubscriptionDeletedEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		logger.Error(logger.EventGeneral, "Failed to unmarshal subscription deleted event", logger.Fields("error", err.Error()))
		return
	}

	logger.Info(logger.EventGeneral, "Received subscription deleted event", logger.Fields(
		"user_id", event.UserID,
		"type", event.Type,
		"target_id", event.TargetID,
	))

	if event.Type != "GENRE" {
		logger.Info(logger.EventGeneral, "Ignoring non-genre subscription deletion", logger.Fields("type", event.Type))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := c.repo.RemoveSubscription(ctx, event.UserID, event.TargetID); err != nil {
		logger.Error(logger.EventGeneral, "Failed to remove subscription from event", logger.Fields(
			"user_id", event.UserID,
			"target_id", event.TargetID,
			"error", err.Error(),
		))
	}
}
