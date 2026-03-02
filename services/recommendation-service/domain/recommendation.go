package domain

type RecommendedTrack struct {
	TrackID   string   `json:"track_id"`
	Title     string   `json:"title"`
	Duration  int      `json:"duration"`
	Genre     string   `json:"genre"`
	AlbumID   string   `json:"album_id,omitempty"`
	ArtistIDs []string `json:"artist_ids"`
	HDFSPath  string   `json:"hdfs_path,omitempty"`
	StreamURL string   `json:"stream_url,omitempty"`
	Reason    string   `json:"reason"`
	Score     float64  `json:"score"`
}
