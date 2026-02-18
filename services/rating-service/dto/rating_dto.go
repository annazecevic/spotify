package dto

import "time"

type CreateOrUpdateRatingRequest struct {
	Value int `json:"value"`
}

type RatingResponse struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TrackID   string    `json:"track_id"`
	Value     int       `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AverageRatingResponse struct {
	TrackID string  `json:"track_id"`
	Average float64 `json:"average"`
	Count   int64   `json:"count"`
}
