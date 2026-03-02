package service

import (
	"context"
	"errors"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/logger"
	"github.com/annazecevic/content-service/messaging"
	"github.com/annazecevic/content-service/repository"
	"go.mongodb.org/mongo-driver/mongo"
)

type ContentService interface {
	CreateGenre(ctx context.Context, g *domain.Genre) error
	ListGenres(ctx context.Context) ([]*domain.Genre, error)
	GetGenreByID(ctx context.Context, id string) (*domain.Genre, error)

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
	GetTrackByID(ctx context.Context, id string) (*domain.Track, error)
	GetTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error)
	UpdateTrackHDFSPath(ctx context.Context, trackID string, hdfsPath string) error
}

type contentService struct {
	repo      repository.ContentRepository
	publisher *messaging.Publisher
}

func NewContentService(repo repository.ContentRepository, publisher *messaging.Publisher) ContentService {
	return &contentService{repo: repo, publisher: publisher}
}

func (s *contentService) CreateGenre(ctx context.Context, g *domain.Genre) error {
	if err := s.repo.CreateGenre(ctx, g); err != nil {
		return err
	}

	if s.publisher != nil {
		go func() {
			if err := s.publisher.PublishGenreCreated(messaging.GenreCreatedEvent{
				GenreID: g.ID,
				Name:    g.Name,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish genre created event", logger.Fields(
					"genre_id", g.ID,
					"error", err.Error(),
				))
			}
		}()
	}

	return nil
}

func (s *contentService) ListGenres(ctx context.Context) ([]*domain.Genre, error) {
	return s.repo.ListGenres(ctx)
}

func (s *contentService) GetGenreByID(ctx context.Context, id string) (*domain.Genre, error) {
	genre, err := s.repo.FindGenreByID(ctx, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("genre not found")
		}
		return nil, err
	}
	return genre, nil
}

func (s *contentService) CreateArtist(ctx context.Context, a *domain.Artist) error {
	if err := s.repo.CreateArtist(ctx, a); err != nil {
		return err
	}

	if s.publisher != nil {
		genreIDs := make([]string, 0, len(a.Genres))
		for _, g := range a.Genres {
			genreIDs = append(genreIDs, g.ID)
		}
		go func() {
			if err := s.publisher.PublishArtistCreated(messaging.ArtistCreatedEvent{
				ArtistID: a.ID,
				Name:     a.Name,
				GenreIDs: genreIDs,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish artist created event", logger.Fields(
					"artist_id", a.ID,
					"error", err.Error(),
				))
			}
		}()
	}

	return nil
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
	if err := s.repo.CreateAlbum(ctx, al); err != nil {
		return err
	}

	if s.publisher != nil && len(al.ArtistIDs) > 0 {
		go func() {
			if err := s.publisher.PublishAlbumCreated(messaging.AlbumCreatedEvent{
				AlbumID:   al.ID,
				Title:     al.Title,
				ArtistIDs: al.ArtistIDs,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish album created event", logger.Fields(
					"album_id", al.ID,
					"error", err.Error(),
				))
			}
		}()
	}

	return nil
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

	if err := s.repo.CreateTrack(ctx, t); err != nil {
		return err
	}

	if s.publisher != nil && len(t.ArtistIDs) > 0 {
		go func() {
			if err := s.publisher.PublishTrackCreated(messaging.TrackCreatedEvent{
				TrackID:   t.ID,
				Title:     t.Title,
				ArtistIDs: t.ArtistIDs,
				AlbumID:   t.AlbumID,
				Genre:     t.Genre,
				Duration:  t.Duration,
			}); err != nil {
				logger.Error(logger.EventGeneral, "Failed to publish track created event", logger.Fields(
					"track_id", t.ID,
					"error", err.Error(),
				))
			}
		}()
	}

	return nil
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

func (s *contentService) GetTrackByID(ctx context.Context, id string) (*domain.Track, error) {
	track, err := s.repo.FindTrackByID(ctx, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("track not found")
		}
		return nil, err
	}
	return track, nil
}

func (s *contentService) UpdateTrackHDFSPath(ctx context.Context, trackID string, hdfsPath string) error {
	return s.repo.UpdateTrackHDFSPath(ctx, trackID, hdfsPath)
}
