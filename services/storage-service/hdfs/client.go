package hdfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/colinmarc/hdfs/v2"
)

const (
	BaseDir           = "/spotify/tracks"
	ChunkSize         = 1024 * 1024 // 1MB chunks for streaming
	ReplicationFactor = 2
)

type Client struct {
	client *hdfs.Client
}

type TrackInfo struct {
	TrackID     string    `json:"track_id"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	Path        string    `json:"path"`
	ContentType string    `json:"content_type"`
}

type Stats struct {
	TotalTracks    int   `json:"total_tracks"`
	TotalSize      int64 `json:"total_size"`
	AvailableSpace int64 `json:"available_space"`
}

func NewClient(namenodeAddr string) (*Client, error) {
	client, err := hdfs.New(namenodeAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HDFS namenode: %w", err)
	}

	return &Client{client: client}, nil
}

func (c *Client) Close() error {
	return c.client.Close()
}

func (c *Client) EnsureBaseDir() error {
	err := c.client.MkdirAll(BaseDir, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create base directory: %w", err)
	}
	return nil
}

func (c *Client) getTrackPath(trackID string) string {
	return filepath.Join(BaseDir, trackID+".mp3")
}

func (c *Client) UploadTrack(trackID string, reader io.Reader, size int64) (string, error) {
	path := c.getTrackPath(trackID)

	exists, _ := c.Exists(trackID)
	if exists {
		if err := c.client.Remove(path); err != nil {
			return "", fmt.Errorf("failed to remove existing track: %w", err)
		}
	}

	writer, err := c.client.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create file in HDFS: %w", err)
	}
	defer writer.Close()

	written, err := io.Copy(writer, reader)
	if err != nil {
		c.client.Remove(path)
		return "", fmt.Errorf("failed to write to HDFS: %w", err)
	}

	if size > 0 && written != size {
		c.client.Remove(path)
		return "", fmt.Errorf("size mismatch: expected %d, got %d", size, written)
	}

	return path, nil
}

func (c *Client) DownloadTrack(trackID string) (io.ReadCloser, *TrackInfo, error) {
	path := c.getTrackPath(trackID)

	info, err := c.client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("track not found: %s", trackID)
		}
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}

	reader, err := c.client.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}

	trackInfo := &TrackInfo{
		TrackID:     trackID,
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		Path:        path,
		ContentType: "audio/mpeg",
	}

	return reader, trackInfo, nil
}

func (c *Client) StreamTrack(trackID string, start, end int64) (io.ReadCloser, *TrackInfo, error) {
	path := c.getTrackPath(trackID)

	info, err := c.client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("track not found: %s", trackID)
		}
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}

	reader, err := c.client.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}

	if start > 0 {
		_, err = reader.Seek(start, io.SeekStart)
		if err != nil {
			reader.Close()
			return nil, nil, fmt.Errorf("failed to seek: %w", err)
		}
	}

	trackInfo := &TrackInfo{
		TrackID:     trackID,
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		Path:        path,
		ContentType: "audio/mpeg",
	}

	if end > 0 && end < info.Size() {
		return &limitedReader{reader: reader, remaining: end - start + 1}, trackInfo, nil
	}

	return reader, trackInfo, nil
}

func (c *Client) DeleteTrack(trackID string) error {
	path := c.getTrackPath(trackID)

	exists, _ := c.Exists(trackID)
	if !exists {
		return fmt.Errorf("track not found: %s", trackID)
	}

	if err := c.client.Remove(path); err != nil {
		return fmt.Errorf("failed to delete track: %w", err)
	}

	return nil
}

func (c *Client) Exists(trackID string) (bool, error) {
	path := c.getTrackPath(trackID)
	_, err := c.client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) GetTrackInfo(trackID string) (*TrackInfo, error) {
	path := c.getTrackPath(trackID)

	info, err := c.client.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("track not found: %s", trackID)
		}
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &TrackInfo{
		TrackID:     trackID,
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		Path:        path,
		ContentType: "audio/mpeg",
	}, nil
}

func (c *Client) GetStats() (*Stats, error) {
	files, err := c.client.ReadDir(BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &Stats{TotalTracks: 0, TotalSize: 0}, nil
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var totalSize int64
	trackCount := 0

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".mp3" {
			trackCount++
			totalSize += file.Size()
		}
	}

	fsInfo, err := c.client.StatFs()
	var availableSpace int64
	if err == nil {
		availableSpace = int64(fsInfo.Remaining)
	}

	return &Stats{
		TotalTracks:    trackCount,
		TotalSize:      totalSize,
		AvailableSpace: availableSpace,
	}, nil
}

func (c *Client) ListTracks() ([]TrackInfo, error) {
	files, err := c.client.ReadDir(BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []TrackInfo{}, nil
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var tracks []TrackInfo
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".mp3" {
			trackID := file.Name()[:len(file.Name())-4]
			tracks = append(tracks, TrackInfo{
				TrackID:     trackID,
				Size:        file.Size(),
				ModTime:     file.ModTime(),
				Path:        filepath.Join(BaseDir, file.Name()),
				ContentType: "audio/mpeg",
			})
		}
	}

	return tracks, nil
}

type limitedReader struct {
	reader    io.ReadCloser
	remaining int64
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	if lr.remaining <= 0 {
		return 0, io.EOF
	}

	if int64(len(p)) > lr.remaining {
		p = p[:lr.remaining]
	}

	n, err := lr.reader.Read(p)
	lr.remaining -= int64(n)
	return n, err
}

func (lr *limitedReader) Close() error {
	return lr.reader.Close()
}
