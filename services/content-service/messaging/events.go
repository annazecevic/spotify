package messaging

const (
	SubjectAlbumCreated  = "content.album.created"
	SubjectTrackCreated  = "content.track.created"
	SubjectArtistCreated = "content.artist.created"
)

type AlbumCreatedEvent struct {
	AlbumID   string   `json:"album_id"`
	Title     string   `json:"title"`
	ArtistIDs []string `json:"artist_ids"`
}

type TrackCreatedEvent struct {
	TrackID   string   `json:"track_id"`
	Title     string   `json:"title"`
	ArtistIDs []string `json:"artist_ids"`
	AlbumID   string   `json:"album_id,omitempty"`
}

type ArtistCreatedEvent struct {
	ArtistID string   `json:"artist_id"`
	Name     string   `json:"name"`
	GenreIDs []string `json:"genre_ids"`
}
