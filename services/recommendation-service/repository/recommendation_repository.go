package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/annazecevic/recommendation-service/domain"
	"github.com/annazecevic/recommendation-service/logger"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type RecommendationRepository interface {
	SyncUser(ctx context.Context, userID string) error
	SyncTrack(ctx context.Context, track TrackData) error
	SyncGenre(ctx context.Context, genreID, genreName string) error
	SyncArtist(ctx context.Context, artistID, artistName string) error
	SyncRating(ctx context.Context, userID, trackID string, value int) error
	SyncSubscription(ctx context.Context, userID, genreID string) error
	RemoveSubscription(ctx context.Context, userID, genreID string) error
	RemoveRating(ctx context.Context, userID, trackID string) error
	SyncTrackGenre(ctx context.Context, trackID, genreName string) error
	SyncTrackArtist(ctx context.Context, trackID, artistID string) error

	GetSubscribedGenreTracks(ctx context.Context, userID string, limit int) ([]domain.RecommendedTrack, error)
	GetTrendingTrackOutsideSubscriptions(ctx context.Context, userID string) (*domain.RecommendedTrack, error)
}

type TrackData struct {
	ID        string
	Title     string
	Duration  int
	Genre     string
	AlbumID   string
	ArtistIDs []string
	HDFSPath  string
}

type recommendationRepository struct {
	driver neo4j.DriverWithContext
}

func NewRecommendationRepository(driver neo4j.DriverWithContext) RecommendationRepository {
	return &recommendationRepository{driver: driver}
}

func (r *recommendationRepository) SyncUser(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		"MERGE (u:User {id: $userID})",
		map[string]interface{}{"userID": userID},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync user to Neo4j", logger.Fields("user_id", userID, "error", err.Error()))
		return fmt.Errorf("failed to sync user: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncTrack(ctx context.Context, track TrackData) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MERGE (t:Track {id: $id})
		 SET t.title = $title, t.duration = $duration, t.genre = $genre, 
		     t.album_id = $albumID, t.hdfs_path = $hdfsPath`,
		map[string]interface{}{
			"id":       track.ID,
			"title":    track.Title,
			"duration": track.Duration,
			"genre":    track.Genre,
			"albumID":  track.AlbumID,
			"hdfsPath": track.HDFSPath,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync track to Neo4j", logger.Fields("track_id", track.ID, "error", err.Error()))
		return fmt.Errorf("failed to sync track: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncGenre(ctx context.Context, genreID, genreName string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		"MERGE (g:Genre {id: $id}) SET g.name = $name",
		map[string]interface{}{"id": genreID, "name": genreName},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync genre to Neo4j", logger.Fields("genre_id", genreID, "error", err.Error()))
		return fmt.Errorf("failed to sync genre: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncArtist(ctx context.Context, artistID, artistName string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		"MERGE (a:Artist {id: $id}) SET a.name = $name",
		map[string]interface{}{"id": artistID, "name": artistName},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync artist to Neo4j", logger.Fields("artist_id", artistID, "error", err.Error()))
		return fmt.Errorf("failed to sync artist: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncRating(ctx context.Context, userID, trackID string, value int) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MERGE (u:User {id: $userID})
		 MERGE (t:Track {id: $trackID})
		 MERGE (u)-[r:RATED]->(t)
		 SET r.value = $value`,
		map[string]interface{}{
			"userID":  userID,
			"trackID": trackID,
			"value":   value,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync rating to Neo4j", logger.Fields(
			"user_id", userID, "track_id", trackID, "error", err.Error(),
		))
		return fmt.Errorf("failed to sync rating: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncSubscription(ctx context.Context, userID, genreID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MERGE (u:User {id: $userID})
		 MERGE (g:Genre {id: $genreID})
		 MERGE (u)-[:SUBSCRIBED_TO]->(g)`,
		map[string]interface{}{
			"userID":  userID,
			"genreID": genreID,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync subscription to Neo4j", logger.Fields(
			"user_id", userID, "genre_id", genreID, "error", err.Error(),
		))
		return fmt.Errorf("failed to sync subscription: %w", err)
	}
	return nil
}

func (r *recommendationRepository) RemoveSubscription(ctx context.Context, userID, genreID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MATCH (u:User {id: $userID})-[r:SUBSCRIBED_TO]->(g:Genre {id: $genreID})
		 DELETE r`,
		map[string]interface{}{
			"userID":  userID,
			"genreID": genreID,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to remove subscription from Neo4j", logger.Fields(
			"user_id", userID, "genre_id", genreID, "error", err.Error(),
		))
		return fmt.Errorf("failed to remove subscription: %w", err)
	}
	return nil
}

func (r *recommendationRepository) RemoveRating(ctx context.Context, userID, trackID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MATCH (u:User {id: $userID})-[r:RATED]->(t:Track {id: $trackID})
		 DELETE r`,
		map[string]interface{}{
			"userID":  userID,
			"trackID": trackID,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to remove rating from Neo4j", logger.Fields(
			"user_id", userID, "track_id", trackID, "error", err.Error(),
		))
		return fmt.Errorf("failed to remove rating: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncTrackGenre(ctx context.Context, trackID, genreName string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MATCH (t:Track {id: $trackID})
		 MATCH (g:Genre {name: $genreName})
		 MERGE (t)-[:BELONGS_TO]->(g)`,
		map[string]interface{}{
			"trackID":   trackID,
			"genreName": genreName,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync track-genre relation in Neo4j", logger.Fields(
			"track_id", trackID, "genre_name", genreName, "error", err.Error(),
		))
		return fmt.Errorf("failed to sync track-genre: %w", err)
	}
	return nil
}

func (r *recommendationRepository) SyncTrackArtist(ctx context.Context, trackID, artistID string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.Run(ctx,
		`MATCH (t:Track {id: $trackID})
		 MERGE (a:Artist {id: $artistID})
		 MERGE (t)-[:PERFORMED_BY]->(a)`,
		map[string]interface{}{
			"trackID":  trackID,
			"artistID": artistID,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to sync track-artist relation in Neo4j", logger.Fields(
			"track_id", trackID, "artist_id", artistID, "error", err.Error(),
		))
		return fmt.Errorf("failed to sync track-artist: %w", err)
	}
	return nil
}

func (r *recommendationRepository) GetSubscribedGenreTracks(ctx context.Context, userID string, limit int) ([]domain.RecommendedTrack, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (u:User {id: $userID})-[:SUBSCRIBED_TO]->(g:Genre)<-[:BELONGS_TO]-(t:Track)
		 OPTIONAL MATCH (u)-[myRating:RATED]->(t)
		 WHERE myRating IS NULL OR myRating.value >= 4
		 OPTIONAL MATCH (other:User)-[otherRating:RATED]->(t)
		 WHERE otherRating.value = 5
		 WITH t, g, myRating, count(otherRating) AS fiveStarCount
		 RETURN t.id AS track_id, t.title AS title, t.duration AS duration, 
		        t.genre AS genre, t.album_id AS album_id, t.hdfs_path AS hdfs_path,
		        g.name AS genre_name,
		        CASE WHEN myRating IS NULL THEN 0 ELSE myRating.value END AS my_rating,
		        fiveStarCount,
		        CASE WHEN myRating IS NOT NULL AND myRating.value = 5 THEN 3
		             WHEN myRating IS NOT NULL AND myRating.value = 4 THEN 2
		             ELSE 1 END + fiveStarCount * 0.1 AS score
		 ORDER BY score DESC, fiveStarCount DESC
		 LIMIT $limit`,
		map[string]interface{}{
			"userID": userID,
			"limit":  limit,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to get subscribed genre tracks", logger.Fields(
			"user_id", userID, "error", err.Error(),
		))
		return nil, fmt.Errorf("failed to get recommendations: %w", err)
	}

	var tracks []domain.RecommendedTrack
	for result.Next(ctx) {
		record := result.Record()

		trackID, _ := record.Get("track_id")
		title, _ := record.Get("title")
		duration, _ := record.Get("duration")
		genre, _ := record.Get("genre")
		albumID, _ := record.Get("album_id")
		hdfsPath, _ := record.Get("hdfs_path")
		genreName, _ := record.Get("genre_name")
		score, _ := record.Get("score")

		track := domain.RecommendedTrack{
			TrackID:  safeString(trackID),
			Title:    safeString(title),
			Duration: safeInt(duration),
			Genre:    safeString(genre),
			AlbumID:  safeString(albumID),
			HDFSPath: safeString(hdfsPath),
			Reason:   fmt.Sprintf("Pripada žanru '%s' na koji ste pretplaćeni", safeString(genreName)),
			Score:    safeFloat(score),
		}

		tracks = append(tracks, track)
	}

	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("error iterating results: %w", err)
	}

	return tracks, nil
}

func (r *recommendationRepository) GetTrendingTrackOutsideSubscriptions(ctx context.Context, userID string) (*domain.RecommendedTrack, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	session := r.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.Run(ctx,
		`MATCH (t:Track)-[:BELONGS_TO]->(g:Genre)
		 WHERE NOT EXISTS {
		   MATCH (u:User {id: $userID})-[:SUBSCRIBED_TO]->(g)
		 }
		 MATCH (other:User)-[r:RATED]->(t)
		 WHERE r.value = 5
		 WITH t, g, count(r) AS fiveStarCount
		 ORDER BY fiveStarCount DESC
		 LIMIT 1
		 RETURN t.id AS track_id, t.title AS title, t.duration AS duration,
		        t.genre AS genre, t.album_id AS album_id, t.hdfs_path AS hdfs_path,
		        g.name AS genre_name, fiveStarCount`,
		map[string]interface{}{
			"userID": userID,
		},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to get trending track outside subscriptions", logger.Fields(
			"user_id", userID, "error", err.Error(),
		))
		return nil, fmt.Errorf("failed to get trending track: %w", err)
	}

	if !result.Next(ctx) {
		return nil, nil
	}

	record := result.Record()
	trackID, _ := record.Get("track_id")
	title, _ := record.Get("title")
	duration, _ := record.Get("duration")
	genre, _ := record.Get("genre")
	albumID, _ := record.Get("album_id")
	hdfsPath, _ := record.Get("hdfs_path")
	genreName, _ := record.Get("genre_name")
	fiveStarCount, _ := record.Get("fiveStarCount")

	track := &domain.RecommendedTrack{
		TrackID:  safeString(trackID),
		Title:    safeString(title),
		Duration: safeInt(duration),
		Genre:    safeString(genre),
		AlbumID:  safeString(albumID),
		HDFSPath: safeString(hdfsPath),
		Reason:   fmt.Sprintf("Trending pesma iz žanra '%s' sa %d ocena 5", safeString(genreName), safeInt64(fiveStarCount)),
		Score:    float64(safeInt64(fiveStarCount)),
	}

	return track, nil
}

func safeString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func safeInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return int(val)
	case int:
		return val
	case float64:
		return int(val)
	default:
		return 0
	}
}

func safeInt64(v interface{}) int64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	default:
		return 0
	}
}

func safeFloat(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int64:
		return float64(val)
	case int:
		return float64(val)
	default:
		return 0
	}
}
