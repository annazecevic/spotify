package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/annazecevic/recommendation-service/domain"
	"github.com/annazecevic/recommendation-service/logger"
	"github.com/annazecevic/recommendation-service/repository"
	"github.com/annazecevic/recommendation-service/resilience"
)

type RecommendationService interface {
	GetRecommendations(ctx context.Context, userID string) ([]domain.RecommendedTrack, *domain.RecommendedTrack, error)
	SyncAllData(ctx context.Context, userID string) error
}

type recommendationService struct {
	repo                    repository.RecommendationRepository
	contentServiceURL       string
	ratingServiceURL        string
	subscriptionsServiceURL string
	// 2.7.1 Configured HTTP client
	httpClient *http.Client
	// 2.7.4 Circuit breakers per downstream service
	contentCB       *resilience.CircuitBreaker
	ratingCB        *resilience.CircuitBreaker
	subscriptionsCB *resilience.CircuitBreaker
	// 2.7.5 Retry configuration
	retryCfg resilience.RetryConfig
}

func NewRecommendationService(
	repo repository.RecommendationRepository,
	contentServiceURL, ratingServiceURL, subscriptionsServiceURL string,
) RecommendationService {
	return &recommendationService{
		repo:                    repo,
		contentServiceURL:       contentServiceURL,
		ratingServiceURL:        ratingServiceURL,
		subscriptionsServiceURL: subscriptionsServiceURL,
		httpClient:              resilience.NewHTTPClient(),
		contentCB:               resilience.NewCircuitBreaker("content-service", 5, 3, 30*time.Second),
		ratingCB:                resilience.NewCircuitBreaker("rating-service", 5, 3, 30*time.Second),
		subscriptionsCB:         resilience.NewCircuitBreaker("subscriptions-service", 5, 3, 30*time.Second),
		retryCfg:                resilience.DefaultRetryConfig(),
	}
}

type Track struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Duration  int      `json:"duration"`
	Genre     string   `json:"genre"`
	AlbumID   string   `json:"album_id"`
	ArtistIDs []string `json:"artist_ids"`
	HDFSPath  string   `json:"hdfs_path"`
}

type Genre struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type Artist struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Genres []Genre `json:"genres"`
}

type Rating struct {
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	TrackID string `json:"track_id"`
	Value   int    `json:"value"`
}

type Subscription struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
}

type SubscriptionsResponse struct {
	Data  []Subscription `json:"data"`
	Count int            `json:"count"`
}

func (s *recommendationService) GetRecommendations(ctx context.Context, userID string) ([]domain.RecommendedTrack, *domain.RecommendedTrack, error) {
	if err := s.repo.SyncUser(ctx, userID); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to ensure user node exists", logger.Fields(
			"user_id", userID, "error", err.Error(),
		))
	}

	subscribedTracks, err := s.repo.GetSubscribedGenreTracks(ctx, userID, 50)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get subscribed genre tracks: %w", err)
	}

	trendingTrack, err := s.repo.GetTrendingTrackOutsideSubscriptions(ctx, userID)
	if err != nil {
		logger.Warn(logger.EventGeneral, "Failed to get trending track", logger.Fields(
			"user_id", userID, "error", err.Error(),
		))
	}

	return subscribedTracks, trendingTrack, nil
}

func (s *recommendationService) SyncAllData(ctx context.Context, userID string) error {
	genres, err := s.fetchGenres(ctx)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch genres", logger.Fields("error", err.Error()))
		return fmt.Errorf("failed to fetch genres: %w", err)
	}
	for _, g := range genres {
		if err := s.repo.SyncGenre(ctx, g.ID, g.Name); err != nil {
			logger.Warn(logger.EventDBError, "Failed to sync genre", logger.Fields("genre_id", g.ID, "error", err.Error()))
		}
	}

	artists, err := s.fetchArtists(ctx)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch artists", logger.Fields("error", err.Error()))
		return fmt.Errorf("failed to fetch artists: %w", err)
	}
	for _, a := range artists {
		if err := s.repo.SyncArtist(ctx, a.ID, a.Name); err != nil {
			logger.Warn(logger.EventDBError, "Failed to sync artist", logger.Fields("artist_id", a.ID, "error", err.Error()))
		}
	}

	tracks, err := s.fetchTracks(ctx)
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to fetch tracks", logger.Fields("error", err.Error()))
		return fmt.Errorf("failed to fetch tracks: %w", err)
	}
	for _, t := range tracks {
		trackData := repository.TrackData{
			ID:        t.ID,
			Title:     t.Title,
			Duration:  t.Duration,
			Genre:     t.Genre,
			AlbumID:   t.AlbumID,
			ArtistIDs: t.ArtistIDs,
			HDFSPath:  t.HDFSPath,
		}
		if err := s.repo.SyncTrack(ctx, trackData); err != nil {
			logger.Warn(logger.EventDBError, "Failed to sync track", logger.Fields("track_id", t.ID, "error", err.Error()))
			continue
		}
		if t.Genre != "" {
			if err := s.repo.SyncTrackGenre(ctx, t.ID, t.Genre); err != nil {
				logger.Warn(logger.EventDBError, "Failed to sync track-genre", logger.Fields("track_id", t.ID, "genre", t.Genre, "error", err.Error()))
			}
		}
		for _, artistID := range t.ArtistIDs {
			if err := s.repo.SyncTrackArtist(ctx, t.ID, artistID); err != nil {
				logger.Warn(logger.EventDBError, "Failed to sync track-artist", logger.Fields("track_id", t.ID, "artist_id", artistID, "error", err.Error()))
			}
		}
	}

	if err := s.repo.SyncUser(ctx, userID); err != nil {
		logger.Error(logger.EventDBError, "Failed to sync user", logger.Fields("user_id", userID, "error", err.Error()))
	}

	subscriptions, err := s.fetchUserSubscriptions(ctx, userID)
	if err != nil {
		logger.Warn(logger.EventGeneral, "Failed to fetch subscriptions", logger.Fields("user_id", userID, "error", err.Error()))
	} else {
		for _, sub := range subscriptions {
			if sub.Type == "GENRE" {
				if err := s.repo.SyncSubscription(ctx, userID, sub.TargetID); err != nil {
					logger.Warn(logger.EventDBError, "Failed to sync subscription", logger.Fields(
						"user_id", userID, "genre_id", sub.TargetID, "error", err.Error(),
					))
				}
			}
		}
	}

	for _, t := range tracks {
		ratings, err := s.fetchTrackRatings(ctx, t.ID, userID)
		if err != nil {
			logger.Warn(logger.EventGeneral, "Failed to fetch ratings for track", logger.Fields("track_id", t.ID, "error", err.Error()))
			continue
		}
		for _, r := range ratings {
			if err := s.repo.SyncRating(ctx, r.UserID, r.TrackID, r.Value); err != nil {
				logger.Warn(logger.EventDBError, "Failed to sync rating", logger.Fields(
					"user_id", r.UserID, "track_id", r.TrackID, "error", err.Error(),
				))
			}
		}
	}

	logger.Info(logger.EventGeneral, "Data sync completed", logger.Fields(
		"user_id", userID,
		"genres", len(genres),
		"artists", len(artists),
		"tracks", len(tracks),
	))

	return nil
}

func (s *recommendationService) fetchGenres(ctx context.Context) ([]Genre, error) {
	url := fmt.Sprintf("%s/content/genres", s.contentServiceURL)
	var genres []Genre
	if err := s.httpGet(ctx, url, &genres); err != nil {
		return nil, err
	}
	return genres, nil
}

func (s *recommendationService) fetchArtists(ctx context.Context) ([]Artist, error) {
	url := fmt.Sprintf("%s/content/artists", s.contentServiceURL)
	var artists []Artist
	if err := s.httpGet(ctx, url, &artists); err != nil {
		return nil, err
	}
	return artists, nil
}

func (s *recommendationService) fetchTracks(ctx context.Context) ([]Track, error) {
	url := fmt.Sprintf("%s/content/tracks", s.contentServiceURL)
	var tracks []Track
	if err := s.httpGet(ctx, url, &tracks); err != nil {
		return nil, err
	}
	return tracks, nil
}

func (s *recommendationService) fetchUserSubscriptions(ctx context.Context, userID string) ([]Subscription, error) {
	url := fmt.Sprintf("%s/api/v1/subscriptions/me?type=GENRE", s.subscriptionsServiceURL)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "Subscriptions service unavailable, returning empty (fallback)", logger.Fields(
			"user_id", userID, "error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(s.subscriptionsCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-User-ID", userID)
		return s.httpClient.Do(req)
	}, fallback)

	if err != nil || resp == nil {
		return []Subscription{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscriptions service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var subResp SubscriptionsResponse
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subscriptions: %w", err)
	}

	return subResp.Data, nil
}

func (s *recommendationService) fetchTrackRatings(ctx context.Context, trackID string, requestingUserID string) ([]Rating, error) {
	url := fmt.Sprintf("%s/api/v1/ratings/%s/all", s.ratingServiceURL, trackID)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fallback := func(err error) (*http.Response, error) {
		logger.Warn(logger.EventGeneral, "Rating service unavailable, returning empty ratings (fallback)", logger.Fields(
			"track_id", trackID, "error", err.Error(),
		))
		return nil, nil
	}

	resp, err := resilience.Execute(s.ratingCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-User-ID", requestingUserID)
		return s.httpClient.Do(req)
	}, fallback)

	if err != nil || resp == nil {
		return []Rating{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rating service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var ratings []Rating
	if err := json.Unmarshal(body, &ratings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ratings: %w", err)
	}

	return ratings, nil
}

func (s *recommendationService) httpGet(ctx context.Context, url string, target interface{}) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := resilience.Execute(s.contentCB, s.retryCfg, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		return s.httpClient.Do(req)
	}, nil)

	if err != nil {
		return fmt.Errorf("service unavailable at %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("service at %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from %s: %w", url, err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("failed to unmarshal response from %s: %w", url, err)
	}

	return nil
}
