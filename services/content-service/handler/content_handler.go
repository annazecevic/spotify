package handler

import (
	"html"
	"net/http"
	"strings"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/dto"
	"github.com/annazecevic/content-service/logger"
	"github.com/annazecevic/content-service/middleware"
	"github.com/annazecevic/content-service/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ContentHandler struct {
	svc service.ContentService
}

func NewContentHandler(svc service.ContentService) *ContentHandler { return &ContentHandler{svc: svc} }

func (h *ContentHandler) RegisterRoutes(r *gin.Engine) {
	g := r.Group("/content")

	g.GET("/genres", h.ListGenres)
	g.GET("/artists", h.ListArtists)
	g.GET("/artists/search", h.SearchArtists)
	g.GET("/artists/:id", h.GetArtist)
	g.GET("/artists/:id/albums", h.GetArtistAlbums)
	g.GET("/albums", h.ListAlbums)
	g.GET("/albums/search", h.SearchAlbums)
	g.GET("/albums/:id", h.GetAlbum)
	g.GET("/albums/:id/tracks", h.GetAlbumTracks)
	g.GET("/tracks", h.ListTracks)
	g.GET("/tracks/search", h.SearchTracks)

	g.POST("/genres", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateGenre)
	g.POST("/artists", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateArtist)
	g.POST("/albums", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateAlbum)
	g.POST("/tracks", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateTrack)

	g.PUT("/artists/:id", middleware.AuthMiddleware(), middleware.AdminOnly(), h.UpdateArtist)
	g.PUT("/tracks/:id/hdfs-path", middleware.AuthMiddleware(), middleware.AdminOnly(), h.UpdateTrackHDFSPath)
}

// --- Admin CRUD operations (all require admin role via middleware) ---

func (h *ContentHandler) CreateGenre(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req dto.CreateGenreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid create genre request", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Name = sanitizeInput(req.Name)
	req.Desc = sanitizeInput(req.Desc)

	if err := validateStringLength(req.Name, 2, 50); err != nil {
		logger.Warn(logger.EventValidationFailure, "Genre name validation failed", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "genre name: " + err.Error()})
		return
	}

	if err := validateStringLength(req.Desc, 0, 500); err != nil {
		logger.Warn(logger.EventValidationFailure, "Genre description validation failed", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "genre description: " + err.Error()})
		return
	}

	g := &domain.Genre{
		ID:   generateID(),
		Name: req.Name,
		Desc: req.Desc,
	}
	if err := h.svc.CreateGenre(c.Request.Context(), g); err != nil {
		logger.Error(logger.EventGeneral, "Failed to create genre", logger.Fields(
			"admin_id", adminID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Security(logger.EventAdminActivity, "Genre created", logger.Fields(
		"admin_id", adminID,
		"genre_id", g.ID,
		"genre_name", g.Name,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusCreated, g)
}

func (h *ContentHandler) ListGenres(c *gin.Context) {
	out, err := h.svc.ListGenres(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) GetArtist(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artist id is required"})
		return
	}

	artist, err := h.svc.GetArtistByID(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "artist not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, artist)
}

func (h *ContentHandler) GetArtistAlbums(c *gin.Context) {
	artistID := c.Param("id")
	if artistID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artist id is required"})
		return
	}

	albums, err := h.svc.GetAlbumsByArtistID(c.Request.Context(), artistID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, albums)
}

func (h *ContentHandler) GetAlbum(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "album id is required"})
		return
	}

	album, err := h.svc.GetAlbumByID(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "album not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, album)
}

func (h *ContentHandler) GetAlbumTracks(c *gin.Context) {
	albumID := c.Param("id")
	if albumID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "album id is required"})
		return
	}

	tracks, err := h.svc.GetTracksByAlbumID(c.Request.Context(), albumID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tracks)
}

func (h *ContentHandler) CreateArtist(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req dto.CreateArtistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid create artist request", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Name = sanitizeInput(req.Name)
	req.About = sanitizeInput(req.About)

	if err := validateStringLength(req.Name, 2, 100); err != nil {
		logger.Warn(logger.EventValidationFailure, "Artist name validation failed", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "artist name: " + err.Error()})
		return
	}

	a := &domain.Artist{
		ID:     generateID(),
		Name:   req.Name,
		Genres: req.Genres,
		About:  req.About,
	}
	if err := h.svc.CreateArtist(c.Request.Context(), a); err != nil {
		logger.Error(logger.EventGeneral, "Failed to create artist", logger.Fields(
			"admin_id", adminID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Security(logger.EventAdminActivity, "Artist created", logger.Fields(
		"admin_id", adminID,
		"artist_id", a.ID,
		"artist_name", a.Name,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusCreated, a)
}

func (h *ContentHandler) ListArtists(c *gin.Context) {
	out, err := h.svc.ListArtists(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) SearchArtists(c *gin.Context) {
	query := c.Query("q")
	genreID := c.Query("genre")

	query = sanitizeInput(query)
	genreID = sanitizeInput(genreID)

	out, err := h.svc.SearchArtists(c.Request.Context(), query, genreID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) UpdateArtist(c *gin.Context) {
	adminID := c.GetString("user_id")

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artist id is required"})
		return
	}

	var req dto.UpdateArtistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid update artist request", logger.Fields(
			"admin_id", adminID,
			"artist_id", id,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := h.svc.GetArtistByID(c.Request.Context(), id)
	if err != nil {
		if err.Error() == "artist not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})

	if req.Name != "" {
		req.Name = sanitizeInput(req.Name)
		if err := validateStringLength(req.Name, 2, 100); err != nil {
			logger.Warn(logger.EventValidationFailure, "Artist name validation failed", logger.Fields(
				"admin_id", adminID,
				"artist_id", id,
				"ip", c.ClientIP(),
				"error", err.Error(),
			))
			c.JSON(http.StatusBadRequest, gin.H{"error": "artist name: " + err.Error()})
			return
		}
		updates["name"] = req.Name
	}

	if req.About != "" {
		req.About = sanitizeInput(req.About)
		updates["about"] = req.About
	}

	if req.Genres != nil {
		updates["genres"] = req.Genres
	}

	if len(updates) == 0 {
		logger.Warn(logger.EventValidationFailure, "No fields provided for artist update", logger.Fields(
			"admin_id", adminID,
			"artist_id", id,
			"ip", c.ClientIP(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	if err := h.svc.UpdateArtist(c.Request.Context(), id, updates); err != nil {
		logger.Error(logger.EventGeneral, "Failed to update artist", logger.Fields(
			"admin_id", adminID,
			"artist_id", id,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	updatedArtist, err := h.svc.GetArtistByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "artist updated but failed to fetch updated data"})
		return
	}

	logger.Security(logger.EventAdminActivity, "Artist updated", logger.Fields(
		"admin_id", adminID,
		"artist_id", id,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusOK, updatedArtist)
}

func (h *ContentHandler) CreateAlbum(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req dto.CreateAlbumRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid create album request", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Title = sanitizeInput(req.Title)

	if err := validateStringLength(req.Title, 1, 200); err != nil {
		logger.Warn(logger.EventValidationFailure, "Album title validation failed", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "album title: " + err.Error()})
		return
	}

	al := &domain.Album{
		ID:        generateID(),
		Title:     req.Title,
		Released:  req.Released,
		Genre:     req.Genre,
		ArtistIDs: req.ArtistIDs,
	}
	if err := h.svc.CreateAlbum(c.Request.Context(), al); err != nil {
		logger.Error(logger.EventGeneral, "Failed to create album", logger.Fields(
			"admin_id", adminID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Security(logger.EventAdminActivity, "Album created", logger.Fields(
		"admin_id", adminID,
		"album_id", al.ID,
		"album_title", al.Title,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusCreated, al)
}

func (h *ContentHandler) SearchAlbums(c *gin.Context) {
	query := c.Query("q")
	query = sanitizeInput(query)

	out, err := h.svc.SearchAlbums(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) ListAlbums(c *gin.Context) {
	out, err := h.svc.ListAlbums(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) CreateTrack(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req dto.CreateTrackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid create track request", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Title = sanitizeInput(req.Title)

	if err := validateStringLength(req.Title, 1, 200); err != nil {
		logger.Warn(logger.EventValidationFailure, "Track title validation failed", logger.Fields(
			"admin_id", adminID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "track title: " + err.Error()})
		return
	}

	if req.Duration < 1 || req.Duration > 7200 {
		logger.Warn(logger.EventValidationFailure, "Invalid track duration", logger.Fields(
			"admin_id", adminID,
			"duration", req.Duration,
			"ip", c.ClientIP(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid track duration"})
		return
	}

	t := &domain.Track{
		ID:        generateID(),
		Title:     req.Title,
		Duration:  req.Duration,
		Genre:     req.Genre,
		AlbumID:   req.AlbumID,
		ArtistIDs: req.ArtistIDs,
	}
	if err := h.svc.CreateTrack(c.Request.Context(), t); err != nil {
		logger.Error(logger.EventGeneral, "Failed to create track", logger.Fields(
			"admin_id", adminID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Security(logger.EventAdminActivity, "Track created", logger.Fields(
		"admin_id", adminID,
		"track_id", t.ID,
		"track_title", t.Title,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusCreated, t)
}

func generateID() string {
	return uuid.New().String()
}

func sanitizeInput(input string) string {
	sanitized := html.EscapeString(input)
	sanitized = strings.TrimSpace(sanitized)
	if middleware.CheckXSSPatterns(sanitized) || middleware.CheckSQLInjectionPatterns(sanitized) {
		return ""
	}
	return sanitized
}

func (h *ContentHandler) SearchTracks(c *gin.Context) {
	query := c.Query("q")
	query = sanitizeInput(query)

	out, err := h.svc.SearchTracks(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func validateStringLength(input string, min, max int) error {
	length := len(input)
	if length < min || length > max {
		return &validationError{message: "must be between " + string(rune(min+'0')) + " and " + string(rune(max+'0')) + " characters"}
	}
	return nil
}

type validationError struct {
	message string
}

func (e *validationError) Error() string {
	return e.message
}

func (h *ContentHandler) ListTracks(c *gin.Context) {
	out, err := h.svc.ListTracks(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) UpdateTrackHDFSPath(c *gin.Context) {
	adminID := c.GetString("user_id")

	trackID := c.Param("id")
	if trackID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track id is required"})
		return
	}

	var req struct {
		HDFSPath string `json:"hdfs_path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid HDFS path update request", logger.Fields(
			"admin_id", adminID,
			"track_id", trackID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.UpdateTrackHDFSPath(c.Request.Context(), trackID, req.HDFSPath); err != nil {
		logger.Error(logger.EventGeneral, "Failed to update track HDFS path", logger.Fields(
			"admin_id", adminID,
			"track_id", trackID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Security(logger.EventAdminActivity, "Track HDFS path updated", logger.Fields(
		"admin_id", adminID,
		"track_id", trackID,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusOK, gin.H{"message": "hdfs_path updated successfully"})
}
