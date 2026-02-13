package domain

import "time"

type SubscriptionType string

const (
	SubscriptionTypeArtist SubscriptionType = "ARTIST"
	SubscriptionTypeGenre  SubscriptionType = "GENRE"
)

type Subscription struct {
	ID        string           `bson:"id" json:"id"`
	UserID    string           `bson:"user_id" json:"user_id"`
	Type      SubscriptionType `bson:"type" json:"type"`
	TargetID  string           `bson:"target_id" json:"target_id"`
	Name      string           `bson:"name" json:"name"`
	CreatedAt time.Time        `bson:"created_at" json:"created_at"`
}
