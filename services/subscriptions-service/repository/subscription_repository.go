package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/annazecevic/subscriptions-service/domain"
	"github.com/annazecevic/subscriptions-service/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SubscriptionRepository interface {
	Create(subscription *domain.Subscription) error
	GetByUserID(userID string) ([]domain.Subscription, error)
	GetByUserIDAndType(userID string, subType domain.SubscriptionType) ([]domain.Subscription, error)
	GetByUserIDAndTarget(userID string, targetID string) (*domain.Subscription, error)
	Delete(userID string, subscriptionID string) error
	GetSubscribersByTarget(targetID string, subType domain.SubscriptionType) ([]domain.Subscription, error)
}

type subscriptionRepository struct {
	collection *mongo.Collection
}

func NewSubscriptionRepository(db *mongo.Database) SubscriptionRepository {
	collection := db.Collection("subscriptions")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "target_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "type", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "target_id", Value: 1}, {Key: "type", Value: 1}},
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		logger.Warn(logger.EventDBError, "Failed to create indexes", logger.Fields("error", err.Error()))
	}

	return &subscriptionRepository{collection: collection}
}

func (r *subscriptionRepository) Create(subscription *domain.Subscription) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.collection.InsertOne(ctx, subscription)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("subscription already exists")
		}
		logger.Error(logger.EventDBError, "Error creating subscription", logger.Fields(
			"user_id", subscription.UserID,
			"target_id", subscription.TargetID,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to create subscription: %w", err)
	}

	return nil
}

func (r *subscriptionRepository) GetByUserID(userID string) ([]domain.Subscription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		logger.Error(logger.EventDBError, "Error fetching user subscriptions", logger.Fields(
			"user_id", userID,
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch subscriptions: %w", err)
	}
	defer cursor.Close(ctx)

	var subscriptions []domain.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}

func (r *subscriptionRepository) GetByUserIDAndType(userID string, subType domain.SubscriptionType) ([]domain.Subscription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID, "type": subType}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		logger.Error(logger.EventDBError, "Error fetching user subscriptions by type", logger.Fields(
			"user_id", userID,
			"type", string(subType),
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch subscriptions: %w", err)
	}
	defer cursor.Close(ctx)

	var subscriptions []domain.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}

func (r *subscriptionRepository) GetByUserIDAndTarget(userID string, targetID string) (*domain.Subscription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID, "target_id": targetID}

	var subscription domain.Subscription
	err := r.collection.FindOne(ctx, filter).Decode(&subscription)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		logger.Error(logger.EventDBError, "Error fetching subscription", logger.Fields(
			"user_id", userID,
			"target_id", targetID,
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch subscription: %w", err)
	}

	return &subscription, nil
}

func (r *subscriptionRepository) Delete(userID string, subscriptionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"id": subscriptionID, "user_id": userID}

	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		logger.Error(logger.EventDBError, "Error deleting subscription", logger.Fields(
			"user_id", userID,
			"subscription_id", subscriptionID,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to delete subscription: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("subscription not found")
	}

	return nil
}

func (r *subscriptionRepository) GetSubscribersByTarget(targetID string, subType domain.SubscriptionType) ([]domain.Subscription, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"target_id": targetID, "type": subType}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		logger.Error(logger.EventDBError, "Error fetching subscribers by target", logger.Fields(
			"target_id", targetID,
			"type", string(subType),
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch subscribers: %w", err)
	}
	defer cursor.Close(ctx)

	var subscriptions []domain.Subscription
	if err := cursor.All(ctx, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to decode subscriptions: %w", err)
	}

	return subscriptions, nil
}
