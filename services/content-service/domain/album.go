package domain

type Album struct {
	ID        string   `bson:"id" json:"id"`
	Title     string   `bson:"title" json:"title"`
	Released  string   `bson:"released" json:"released"` // ISO date
	Genre     Genre    `bson:"genre" json:"genre"`
	ArtistIDs []string `bson:"artist_ids" json:"artist_ids"`
	About     string   `bson:"about,omitempty" json:"about,omitempty"`
}
