package service

import (
	"context"
	"errors"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/repository"
	"go.mongodb.org/mongo-driver/mongo"
)

type ContentService interface {
	CreateGenre(ctx context.Context, g *domain.Genre) error
	ListGenres(ctx context.Context) ([]*domain.Genre, error)

	CreateArtist(ctx context.Context, a *domain.Artist) error
	ListArtists(ctx context.Context) ([]*domain.Artist, error)
	SearchArtists(ctx context.Context, query string, genreID string) ([]*domain.Artist, error)
	GetArtistByID(ctx context.Context, id string) (*domain.Artist, error)
	UpdateArtist(ctx context.Context, id string, updates map[string]interface{}) error

	CreateAlbum(ctx context.Context, al *domain.Album) error
	ListAlbums(ctx context.Context) ([]*domain.Album, error)
	SearchAlbums(ctx context.Context, query string) ([]*domain.Album, error)
	GetAlbumByID(ctx context.Context, id string) (*domain.Album, error)
	GetAlbumsByArtistID(ctx context.Context, artistID string) ([]*domain.Album, error)

	CreateTrack(ctx context.Context, t *domain.Track) error
	ListTracks(ctx context.Context) ([]*domain.Track, error)
	SearchTracks(ctx context.Context, query string) ([]*domain.Track, error)
	GetTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error)
}

type contentService struct {
	repo repository.ContentRepository
}

func NewContentService(repo repository.ContentRepository) ContentService {
	return &contentService{repo: repo}
}

func (s *contentService) CreateGenre(ctx context.Context, g *domain.Genre) error {
	return s.repo.CreateGenre(ctx, g)
}

func (s *contentService) ListGenres(ctx context.Context) ([]*domain.Genre, error) {
	return s.repo.ListGenres(ctx)
}

func (s *contentService) CreateArtist(ctx context.Context, a *domain.Artist) error {
	return s.repo.CreateArtist(ctx, a)
}

func (s *contentService) ListArtists(ctx context.Context) ([]*domain.Artist, error) {
	return s.repo.ListArtists(ctx)
}

func (s *contentService) SearchArtists(ctx context.Context, query string, genreID string) ([]*domain.Artist, error) {
	return s.repo.SearchArtists(ctx, query, genreID)
}

func (s *contentService) GetArtistByID(ctx context.Context, id string) (*domain.Artist, error) {
	artist, err := s.repo.FindArtistByID(ctx, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("artist not found")
		}
		return nil, err
	}
	return artist, nil
}

func (s *contentService) UpdateArtist(ctx context.Context, id string, updates map[string]interface{}) error {
	return s.repo.UpdateArtist(ctx, id, updates)
}

func (s *contentService) CreateAlbum(ctx context.Context, al *domain.Album) error {
	return s.repo.CreateAlbum(ctx, al)
}

func (s *contentService) SearchAlbums(ctx context.Context, query string) ([]*domain.Album, error) {
	return s.repo.SearchAlbums(ctx, query)
}

func (s *contentService) ListAlbums(ctx context.Context) ([]*domain.Album, error) {
	return s.repo.ListAlbums(ctx)
}

func (s *contentService) CreateTrack(ctx context.Context, t *domain.Track) error {
	if t.AlbumID != "" {
		_, err := s.repo.FindAlbumByID(ctx, t.AlbumID)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return errors.New("album not found")
			}
			return err
		}
	}
	return s.repo.CreateTrack(ctx, t)
}

func (s *contentService) SearchTracks(ctx context.Context, query string) ([]*domain.Track, error) {
	return s.repo.SearchTracks(ctx, query)
}

func (s *contentService) ListTracks(ctx context.Context) ([]*domain.Track, error) {
	return s.repo.ListTracks(ctx)
}

func (s *contentService) GetAlbumByID(ctx context.Context, id string) (*domain.Album, error) {
	album, err := s.repo.FindAlbumByID(ctx, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("album not found")
		}
		return nil, err
	}
	return album, nil
}

func (s *contentService) GetAlbumsByArtistID(ctx context.Context, artistID string) ([]*domain.Album, error) {
	return s.repo.FindAlbumsByArtistID(ctx, artistID)
}

func (s *contentService) GetTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error) {
	return s.repo.FindTracksByAlbumID(ctx, albumID)
}
