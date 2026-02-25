package messaging

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/annazecevic/rating-service/logger"
	"github.com/nats-io/nats.go"
)

type Publisher struct {
	conn *nats.Conn
}

func NewPublisher(natsURL string) (*Publisher, error) {
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

	logger.Info(logger.EventGeneral, "Connected to NATS successfully", logger.Fields("url", natsURL))
	return &Publisher{conn: conn}, nil
}

func (p *Publisher) PublishRatingCreated(event RatingEvent) error {
	return p.publish(SubjectRatingCreated, event)
}

func (p *Publisher) PublishRatingUpdated(event RatingEvent) error {
	return p.publish(SubjectRatingUpdated, event)
}

func (p *Publisher) PublishRatingDeleted(event RatingDeletedEvent) error {
	return p.publish(SubjectRatingDeleted, event)
}

func (p *Publisher) publish(subject string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to marshal event", logger.Fields(
			"subject", subject,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := p.conn.Publish(subject, data); err != nil {
		logger.Error(logger.EventGeneral, "Failed to publish event", logger.Fields(
			"subject", subject,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to publish event: %w", err)
	}

	logger.Info(logger.EventGeneral, "Event published", logger.Fields(
		"subject", subject,
		"data_size", len(data),
	))
	return nil
}

func (p *Publisher) Close() {
	if p.conn != nil {
		p.conn.Close()
	}
}
