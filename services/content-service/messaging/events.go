package messaging

const (
	SubjectAlbumCreated  = "content.album.created"
	SubjectTrackCreated  = "content.track.created"
	SubjectArtistCreated = "content.artist.created"
	SubjectGenreCreated  = "content.genre.created"
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
	Genre     string   `json:"genre,omitempty"`
	Duration  int      `json:"duration,omitempty"`
}

type ArtistCreatedEvent struct {
	ArtistID string   `json:"artist_id"`
	Name     string   `json:"name"`
	GenreIDs []string `json:"genre_ids"`
}

type GenreCreatedEvent struct {
	GenreID string `json:"genre_id"`
	Name    string `json:"name"`
}
