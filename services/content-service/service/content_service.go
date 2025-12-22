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

    CreateAlbum(ctx context.Context, al *domain.Album) error
    ListAlbums(ctx context.Context) ([]*domain.Album, error)

    CreateTrack(ctx context.Context, t *domain.Track) error
    ListTracks(ctx context.Context) ([]*domain.Track, error)
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

func (s *contentService) ListGenres(ctx context.Context) ([]*domain.Genre, error) { return s.repo.ListGenres(ctx) }

func (s *contentService) CreateArtist(ctx context.Context, a *domain.Artist) error { return s.repo.CreateArtist(ctx, a) }

func (s *contentService) ListArtists(ctx context.Context) ([]*domain.Artist, error) { return s.repo.ListArtists(ctx) }

func (s *contentService) CreateAlbum(ctx context.Context, al *domain.Album) error { return s.repo.CreateAlbum(ctx, al) }

func (s *contentService) ListAlbums(ctx context.Context) ([]*domain.Album, error) { return s.repo.ListAlbums(ctx) }

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

func (s *contentService) ListTracks(ctx context.Context) ([]*domain.Track, error) { return s.repo.ListTracks(ctx) }
