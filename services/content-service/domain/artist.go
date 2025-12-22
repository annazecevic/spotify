package domain

type Artist struct {
	ID     string  `bson:"id" json:"id"`
	Name   string  `bson:"name" json:"name"`
	Genres []Genre `bson:"genres" json:"genres"`
	About  string  `bson:"about,omitempty" json:"about,omitempty"`
}
