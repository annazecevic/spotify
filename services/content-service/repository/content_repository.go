package repository

import (
	"context"
	"time"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ContentRepository interface {
	CreateGenre(ctx context.Context, g *domain.Genre) error
	ListGenres(ctx context.Context) ([]*domain.Genre, error)
	FindGenreByID(ctx context.Context, id string) (*domain.Genre, error)

	CreateArtist(ctx context.Context, a *domain.Artist) error
	ListArtists(ctx context.Context) ([]*domain.Artist, error)
	SearchArtists(ctx context.Context, query string, genreID string) ([]*domain.Artist, error)
	UpdateArtist(ctx context.Context, id string, updates map[string]interface{}) error
	FindArtistByID(ctx context.Context, id string) (*domain.Artist, error)

	CreateAlbum(ctx context.Context, al *domain.Album) error
	ListAlbums(ctx context.Context) ([]*domain.Album, error)
	SearchAlbums(ctx context.Context, query string) ([]*domain.Album, error)
	FindAlbumByID(ctx context.Context, id string) (*domain.Album, error)
	FindAlbumsByArtistID(ctx context.Context, artistID string) ([]*domain.Album, error)

	CreateTrack(ctx context.Context, t *domain.Track) error
	ListTracks(ctx context.Context) ([]*domain.Track, error)
	SearchTracks(ctx context.Context, query string) ([]*domain.Track, error)
	FindTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error)
	UpdateTrackHDFSPath(ctx context.Context, trackID string, hdfsPath string) error
}

type contentRepository struct {
	genresCol  *mongo.Collection
	artistsCol *mongo.Collection
	albumsCol  *mongo.Collection
	tracksCol  *mongo.Collection
}

func NewContentRepository(db *mongo.Database) ContentRepository {
	genres := db.Collection("genres")
	artists := db.Collection("artists")
	albums := db.Collection("albums")
	tracks := db.Collection("tracks")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = genres.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "name", Value: 1}}, Options: options.Index().SetUnique(true)})
	_, _ = artists.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "name", Value: 1}}, Options: options.Index().SetUnique(true)})
	_, _ = albums.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "title", Value: 1}}, Options: options.Index().SetUnique(false)})
	_, _ = tracks.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "title", Value: 1}}, Options: options.Index().SetUnique(false)})

	return &contentRepository{
		genresCol:  genres,
		artistsCol: artists,
		albumsCol:  albums,
		tracksCol:  tracks,
	}
}

func (r *contentRepository) CreateGenre(ctx context.Context, g *domain.Genre) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.genresCol.InsertOne(ctx, g)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to create genre", logger.Fields(
			"genre_id", g.ID,
			"error", err.Error(),
		))
	}
	return err
}

func (r *contentRepository) ListGenres(ctx context.Context) ([]*domain.Genre, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.genresCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Genre
	for cur.Next(ctx) {
		var g domain.Genre
		if err := cur.Decode(&g); err != nil {
			return nil, err
		}
		out = append(out, &g)
	}
	return out, nil
}

func (r *contentRepository) FindGenreByID(ctx context.Context, id string) (*domain.Genre, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var g domain.Genre
	err := r.genresCol.FindOne(ctx, bson.M{"id": id}).Decode(&g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *contentRepository) CreateArtist(ctx context.Context, a *domain.Artist) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.artistsCol.InsertOne(ctx, a)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to create artist", logger.Fields(
			"artist_id", a.ID,
			"error", err.Error(),
		))
	}
	return err
}

func (r *contentRepository) ListArtists(ctx context.Context) ([]*domain.Artist, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.artistsCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Artist
	for cur.Next(ctx) {
		var a domain.Artist
		if err := cur.Decode(&a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (r *contentRepository) SearchArtists(ctx context.Context, query string, genreID string) ([]*domain.Artist, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := bson.M{}

	if query != "" {
		filter["name"] = bson.M{"$regex": query, "$options": "i"}
	}

	if genreID != "" {
		filter["genres"] = bson.M{
			"$elemMatch": bson.M{"id": genreID},
		}
	}

	cur, err := r.artistsCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*domain.Artist
	for cur.Next(ctx) {
		var a domain.Artist
		if err := cur.Decode(&a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (r *contentRepository) FindArtistByID(ctx context.Context, id string) (*domain.Artist, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var artist domain.Artist
	err := r.artistsCol.FindOne(ctx, bson.M{"id": id}).Decode(&artist)
	if err != nil {
		return nil, err
	}
	return &artist, nil
}

func (r *contentRepository) UpdateArtist(ctx context.Context, id string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if len(updates) == 0 {
		return nil
	}

	update := bson.M{
		"$set": updates,
	}

	result, err := r.artistsCol.UpdateOne(ctx, bson.M{"id": id}, update)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to update artist", logger.Fields(
			"artist_id", id,
			"error", err.Error(),
		))
		return err
	}

	if result.MatchedCount == 0 {
		logger.Security(logger.EventStateChange, "Update attempted for non-existent artist", logger.Fields(
			"artist_id", id,
		))
		return mongo.ErrNoDocuments
	}

	return nil
}

func (r *contentRepository) CreateAlbum(ctx context.Context, al *domain.Album) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.albumsCol.InsertOne(ctx, al)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to create album", logger.Fields(
			"album_id", al.ID,
			"error", err.Error(),
		))
	}
	return err
}

func (r *contentRepository) ListAlbums(ctx context.Context) ([]*domain.Album, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.albumsCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Album
	for cur.Next(ctx) {
		var a domain.Album
		if err := cur.Decode(&a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (r *contentRepository) SearchAlbums(ctx context.Context, query string) ([]*domain.Album, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := bson.M{}
	if query != "" {
		filter["title"] = bson.M{"$regex": query, "$options": "i"}
	}

	cur, err := r.albumsCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*domain.Album
	for cur.Next(ctx) {
		var a domain.Album
		if err := cur.Decode(&a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (r *contentRepository) FindAlbumByID(ctx context.Context, id string) (*domain.Album, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var album domain.Album
	err := r.albumsCol.FindOne(ctx, bson.M{"id": id}).Decode(&album)
	if err != nil {
		return nil, err
	}
	return &album, nil
}

func (r *contentRepository) CreateTrack(ctx context.Context, t *domain.Track) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.tracksCol.InsertOne(ctx, t)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to create track", logger.Fields(
			"track_id", t.ID,
			"error", err.Error(),
		))
	}
	return err
}

func (r *contentRepository) ListTracks(ctx context.Context) ([]*domain.Track, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.tracksCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Track
	for cur.Next(ctx) {
		var t domain.Track
		if err := cur.Decode(&t); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, nil
}

func (r *contentRepository) SearchTracks(ctx context.Context, query string) ([]*domain.Track, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := bson.M{}
	if query != "" {
		filter["title"] = bson.M{"$regex": query, "$options": "i"}
	}

	cur, err := r.tracksCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []*domain.Track
	for cur.Next(ctx) {
		var t domain.Track
		if err := cur.Decode(&t); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, nil
}

func (r *contentRepository) FindAlbumsByArtistID(ctx context.Context, artistID string) ([]*domain.Album, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.albumsCol.Find(ctx, bson.M{"artist_ids": artistID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Album
	for cur.Next(ctx) {
		var a domain.Album
		if err := cur.Decode(&a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, nil
}

func (r *contentRepository) FindTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cur, err := r.tracksCol.Find(ctx, bson.M{"album_id": albumID})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []*domain.Track
	for cur.Next(ctx) {
		var t domain.Track
		if err := cur.Decode(&t); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, nil
}

func (r *contentRepository) UpdateTrackHDFSPath(ctx context.Context, trackID string, hdfsPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := r.tracksCol.UpdateOne(
		ctx,
		bson.M{"id": trackID},
		bson.M{"$set": bson.M{"hdfs_path": hdfsPath}},
	)
	if err != nil {
		logger.Error(logger.EventDBError, "Failed to update track HDFS path", logger.Fields(
			"track_id", trackID,
			"error", err.Error(),
		))
		return err
	}

	if result.MatchedCount == 0 {
		logger.Security(logger.EventStateChange, "HDFS path update attempted for non-existent track", logger.Fields(
			"track_id", trackID,
		))
		return mongo.ErrNoDocuments
	}

	return nil
}
