package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/annazecevic/rating-service/domain"
	"github.com/annazecevic/rating-service/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RatingRepository interface {
	CreateRating(rating *domain.Rating) error
	UpdateRating(rating *domain.Rating) error
	DeleteRating(userID string, trackID string) error

	GetByUserIDAndTrackID(userID string, trackID string) (*domain.Rating, error)
	GetByTrackID(trackID string) ([]*domain.Rating, error)

	GetAverageByTrackID(trackID string) (float64, error)
}

type ratingRepository struct {
	collection *mongo.Collection
}

func NewRatingRepository(db *mongo.Database) RatingRepository {
	collection := db.Collection("ratings")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "track_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "track_id", Value: 1}},
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		logger.Warn(logger.EventDBError, "Failed to create indexes for ratings", logger.Fields("error", err.Error()))
	}

	return &ratingRepository{collection: collection}

}

func (r *ratingRepository) CreateRating(rating *domain.Rating) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.collection.InsertOne(ctx, rating)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("rating already exists")
		}
		logger.Error(logger.EventDBError, "Error creating rating", logger.Fields(
			"user_id", rating.UserID,
			"track_id", rating.TrackID,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to create rating: %w", err)
	}
	return nil
}

func (r *ratingRepository) UpdateRating(rating *domain.Rating) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": rating.UserID, "track_id": rating.TrackID}
	update := bson.M{
		"$set": bson.M{
			"value":      rating.Value,
			"updated_at": time.Now(),
		},
	}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		logger.Error(logger.EventDBError, "Error updating rating", logger.Fields(
			"user_id", rating.UserID,
			"track_id", rating.TrackID,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to update rating: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("rating not found")
	}

	return nil
}

func (r *ratingRepository) DeleteRating(userID string, trackID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID, "track_id": trackID}

	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		logger.Error(logger.EventDBError, "Error deleting rating", logger.Fields(
			"user_id", userID,
			"track_id", trackID,
			"error", err.Error(),
		))
		return fmt.Errorf("failed to delete rating: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("rating not found")
	}

	return nil
}

func (r *ratingRepository) GetByUserIDAndTrackID(userID string, trackID string) (*domain.Rating, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"user_id": userID, "track_id": trackID}

	var rating domain.Rating
	err := r.collection.FindOne(ctx, filter).Decode(&rating)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		logger.Error(logger.EventDBError, "Error fetching rating", logger.Fields(
			"user_id", userID,
			"track_id", trackID,
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch rating: %w", err)
	}

	return &rating, nil
}
func (r *ratingRepository) GetByTrackID(trackID string) ([]*domain.Rating, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"track_id": trackID}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		logger.Error(logger.EventDBError, "Error fetching ratings by track", logger.Fields(
			"track_id", trackID,
			"error", err.Error(),
		))
		return nil, fmt.Errorf("failed to fetch ratings: %w", err)
	}
	defer cursor.Close(ctx)

	var ratings []*domain.Rating
	if err := cursor.All(ctx, &ratings); err != nil {
		return nil, fmt.Errorf("failed to decode ratings: %w", err)
	}

	return ratings, nil
}
func (r *ratingRepository) GetAverageByTrackID(trackID string) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"track_id", trackID}}}},
		{{"$group", bson.D{
			{"_id", "$track_id"},
			{"avgValue", bson.D{{"$avg", "$value"}}},
		}}},
	}

	cursor, err := r.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return 0, fmt.Errorf("failed to aggregate ratings: %w", err)
	}
	defer cursor.Close(ctx)

	var result []struct {
		AvgValue float64 `bson:"avgValue"`
	}

	if err := cursor.All(ctx, &result); err != nil {
		return 0, fmt.Errorf("failed to decode aggregation result: %w", err)
	}

	if len(result) == 0 {
		return 0, nil
	}

	return result[0].AvgValue, nil
}
