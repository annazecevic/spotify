package domain

import (
	"time"

	"github.com/gocql/gocql"
)

type NotificationType string

const (
	NotificationTypeNewAlbum  NotificationType = "NEW_ALBUM"
	NotificationTypeNewTrack  NotificationType = "NEW_TRACK"
	NotificationTypeNewArtist NotificationType = "NEW_ARTIST"
)

type Notification struct {
	ID        gocql.UUID       `json:"id"`
	UserID    string           `json:"user_id"`
	Type      NotificationType `json:"type"`
	Message   string           `json:"message"`
	Title     string           `json:"title"`
	CreatedAt time.Time        `json:"created_at"`
	Read      bool             `json:"read"`
	ArtistID  string           `json:"artist_id,omitempty"`
	GenreID   string           `json:"genre_id,omitempty"`
	AlbumID   string           `json:"album_id,omitempty"`
	TrackID   string           `json:"track_id,omitempty"`
}
