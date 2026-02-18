package domain

import "time"

type Rating struct {
	ID        string    `bson:"id" json:"id"`
	UserID    string    `bson:"user_id" json:"user_id"`
	TrackID   string    `bson:"track_id" json:"track_id"`
	Value     int       `bson:"value" json:"value"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}
