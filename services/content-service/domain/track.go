package domain

type Track struct {
	ID        string   `bson:"id" json:"id"`
	Title     string   `bson:"title" json:"title"`
	Duration  int      `bson:"duration" json:"duration"` // seconds
	Genre     string   `bson:"genre" json:"genre"`
	AlbumID   string   `bson:"album_id,omitempty" json:"album_id,omitempty"`
	ArtistIDs []string `bson:"artist_ids" json:"artist_ids"`
}
