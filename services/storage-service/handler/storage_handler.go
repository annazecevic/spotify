package handler

import (
	"fmt"
	"io"
	"net/http"
	"storage-service/hdfs"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type StorageHandler struct {
	hdfsClient *hdfs.Client
}

func NewStorageHandler(client *hdfs.Client) *StorageHandler {
	return &StorageHandler{hdfsClient: client}
}

func (h *StorageHandler) UploadTrack(c *gin.Context) {
	trackID := c.PostForm("track_id")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track_id is required"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	contentType := header.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "audio/") {
		ext := strings.ToLower(header.Filename[strings.LastIndex(header.Filename, ".")+1:])
		if ext != "mp3" && ext != "wav" && ext != "flac" && ext != "m4a" && ext != "ogg" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file type, must be audio"})
			return
		}
	}

	path, err := h.hdfsClient.UploadTrack(trackID, file, header.Size)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to upload: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "track uploaded successfully",
		"track_id":  trackID,
		"hdfs_path": path,
		"size":      header.Size,
	})
}

func (h *StorageHandler) StreamTrack(c *gin.Context) {
	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track_id is required"})
		return
	}

	info, err := h.hdfsClient.GetTrackInfo(trackID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "track not found"})
		return
	}

	rangeHeader := c.GetHeader("Range")
	if rangeHeader == "" {
		reader, _, err := h.hdfsClient.DownloadTrack(trackID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read track"})
			return
		}
		defer reader.Close()

		c.Header("Content-Type", info.ContentType)
		c.Header("Content-Length", strconv.FormatInt(info.Size, 10))
		c.Header("Accept-Ranges", "bytes")

		io.Copy(c.Writer, reader)
		return
	}

	var start, end int64
	rangeHeader = strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeHeader, "-")

	if parts[0] != "" {
		start, _ = strconv.ParseInt(parts[0], 10, 64)
	}
	if len(parts) > 1 && parts[1] != "" {
		end, _ = strconv.ParseInt(parts[1], 10, 64)
	} else {
		end = info.Size - 1
	}

	if start >= info.Size {
		c.Header("Content-Range", fmt.Sprintf("bytes */%d", info.Size))
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if end >= info.Size {
		end = info.Size - 1
	}

	reader, _, err := h.hdfsClient.StreamTrack(trackID, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to stream track"})
		return
	}
	defer reader.Close()

	contentLength := end - start + 1

	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Length", strconv.FormatInt(contentLength, 10))
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size))
	c.Header("Accept-Ranges", "bytes")
	c.Status(http.StatusPartialContent)

	io.Copy(c.Writer, reader)
}

func (h *StorageHandler) GetTrackInfo(c *gin.Context) {
	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track_id is required"})
		return
	}

	info, err := h.hdfsClient.GetTrackInfo(trackID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "track not found"})
		return
	}

	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Length", strconv.FormatInt(info.Size, 10))
	c.Header("Accept-Ranges", "bytes")
	c.Status(http.StatusOK)
}

func (h *StorageHandler) DeleteTrack(c *gin.Context) {
	trackID := c.Param("trackId")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track_id is required"})
		return
	}

	if err := h.hdfsClient.DeleteTrack(trackID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "track deleted successfully",
		"track_id": trackID,
	})
}

func (h *StorageHandler) GetStats(c *gin.Context) {
	stats, err := h.hdfsClient.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get stats: %v", err)})
		return
	}

	c.JSON(http.StatusOK, stats)
}
