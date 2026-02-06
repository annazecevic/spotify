package dto

import "github.com/annazecevic/content-service/domain"

type CreateGenreRequest struct {
	Name string `json:"name" binding:"required"`
	Desc string `json:"desc"`
}

type CreateArtistRequest struct {
	Name   string         `json:"name" binding:"required"`
	Genres []domain.Genre `json:"genres"`
	About  string         `json:"about"`
}

type CreateAlbumRequest struct {
	Title     string       `json:"title" binding:"required"`
	Released  string       `json:"released"`
	Genre     domain.Genre `json:"genre"`
	ArtistIDs []string     `json:"artist_ids"`
}

type CreateTrackRequest struct {
	Title     string   `json:"title" binding:"required"`
	Duration  int      `json:"duration"`
	Genre     string   `json:"genre"`
	AlbumID   string   `json:"album_id"`
	ArtistIDs []string `json:"artist_ids"`
}

type UpdateArtistRequest struct {
	Name   string         `json:"name"`
	Genres []domain.Genre `json:"genres"`
	About  string         `json:"about"`
}
