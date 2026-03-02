package messaging

const (
	SubjectGenreCreated  = "content.genre.created"
	SubjectArtistCreated = "content.artist.created"
	SubjectTrackCreated  = "content.track.created"
	SubjectAlbumCreated  = "content.album.created"

	SubjectRatingCreated = "rating.created"
	SubjectRatingUpdated = "rating.updated"
	SubjectRatingDeleted = "rating.deleted"

	SubjectSubscriptionCreated = "subscription.created"
	SubjectSubscriptionDeleted = "subscription.deleted"
)

type GenreCreatedEvent struct {
	GenreID string `json:"genre_id"`
	Name    string `json:"name"`
}

type ArtistCreatedEvent struct {
	ArtistID string   `json:"artist_id"`
	Name     string   `json:"name"`
	GenreIDs []string `json:"genre_ids"`
}

type TrackCreatedEvent struct {
	TrackID   string   `json:"track_id"`
	Title     string   `json:"title"`
	ArtistIDs []string `json:"artist_ids"`
	AlbumID   string   `json:"album_id,omitempty"`
	Genre     string   `json:"genre,omitempty"`
	Duration  int      `json:"duration,omitempty"`
}

type AlbumCreatedEvent struct {
	AlbumID   string   `json:"album_id"`
	Title     string   `json:"title"`
	ArtistIDs []string `json:"artist_ids"`
}

type RatingEvent struct {
	UserID  string `json:"user_id"`
	TrackID string `json:"track_id"`
	Value   int    `json:"value"`
}

type RatingDeletedEvent struct {
	UserID  string `json:"user_id"`
	TrackID string `json:"track_id"`
}

type SubscriptionCreatedEvent struct {
	UserID   string `json:"user_id"`
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
}

type SubscriptionDeletedEvent struct {
	UserID   string `json:"user_id"`
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
}
