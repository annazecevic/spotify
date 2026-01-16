package repository

import (
	"context"
	"time"

	"github.com/annazecevic/content-service/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ContentRepository interface {
	CreateGenre(ctx context.Context, g *domain.Genre) error
	ListGenres(ctx context.Context) ([]*domain.Genre, error)

	CreateArtist(ctx context.Context, a *domain.Artist) error
	ListArtists(ctx context.Context) ([]*domain.Artist, error)
	UpdateArtist(ctx context.Context, id string, updates map[string]interface{}) error
	FindArtistByID(ctx context.Context, id string) (*domain.Artist, error)

	CreateAlbum(ctx context.Context, al *domain.Album) error
	ListAlbums(ctx context.Context) ([]*domain.Album, error)
	FindAlbumByID(ctx context.Context, id string) (*domain.Album, error)
	FindAlbumsByArtistID(ctx context.Context, artistID string) ([]*domain.Album, error)

	CreateTrack(ctx context.Context, t *domain.Track) error
	ListTracks(ctx context.Context) ([]*domain.Track, error)
	FindTracksByAlbumID(ctx context.Context, albumID string) ([]*domain.Track, error)
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

func (r *contentRepository) CreateArtist(ctx context.Context, a *domain.Artist) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.artistsCol.InsertOne(ctx, a)
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
		return err
	}

	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	return nil
}

func (r *contentRepository) CreateAlbum(ctx context.Context, al *domain.Album) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.albumsCol.InsertOne(ctx, al)
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
