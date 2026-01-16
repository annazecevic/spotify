package handler

import (
	"html"
	"net/http"
	"strings"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/dto"
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
	g.GET("/artists/:id", h.GetArtist)
	g.GET("/artists/:id/albums", h.GetArtistAlbums)
	g.GET("/albums", h.ListAlbums)
	g.GET("/albums/:id", h.GetAlbum)
	g.GET("/albums/:id/tracks", h.GetAlbumTracks)
	g.GET("/tracks", h.ListTracks)

	g.POST("/genres", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateGenre)
	g.POST("/artists", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateArtist)
	g.POST("/albums", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateAlbum)
	g.POST("/tracks", middleware.AuthMiddleware(), middleware.AdminOnly(), h.CreateTrack)

	g.PUT("/artists/:id", middleware.AuthMiddleware(), middleware.AdminOnly(), h.UpdateArtist)
}

func (h *ContentHandler) CreateGenre(c *gin.Context) {
	var req dto.CreateGenreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Input validation and sanitization (2.18)
	req.Name = sanitizeInput(req.Name)
	req.Desc = sanitizeInput(req.Desc)

	if err := validateStringLength(req.Name, 2, 50); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "genre name: " + err.Error()})
		return
	}

	if err := validateStringLength(req.Desc, 0, 500); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "genre description: " + err.Error()})
		return
	}

	g := &domain.Genre{
		ID:   generateID(),
		Name: req.Name,
		Desc: req.Desc,
	}
	if err := h.svc.CreateGenre(c.Request.Context(), g); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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
	var req dto.CreateArtistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Input validation and sanitization (2.18)
	req.Name = sanitizeInput(req.Name)
	req.About = sanitizeInput(req.About)

	if err := validateStringLength(req.Name, 2, 100); err != nil {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
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

func (h *ContentHandler) UpdateArtist(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artist id is required"})
		return
	}

	var req dto.UpdateArtistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	if err := h.svc.UpdateArtist(c.Request.Context(), id, updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	updatedArtist, err := h.svc.GetArtistByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "artist updated but failed to fetch updated data"})
		return
	}

	c.JSON(http.StatusOK, updatedArtist)
}

func (h *ContentHandler) CreateAlbum(c *gin.Context) {
	var req dto.CreateAlbumRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Input validation and sanitization (2.18)
	req.Title = sanitizeInput(req.Title)

	if err := validateStringLength(req.Title, 1, 200); err != nil {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, al)
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
	var req dto.CreateTrackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Input validation and sanitization (2.18)
	req.Title = sanitizeInput(req.Title)

	if err := validateStringLength(req.Title, 1, 200); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "track title: " + err.Error()})
		return
	}

	// Validate duration (numeric validation - 2.18)
	if req.Duration < 1 || req.Duration > 7200 { // 1 second to 2 hours
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, t)
}

// Helper functions for validation and sanitization (2.18)

func generateID() string {
	return uuid.New().String()
}

func sanitizeInput(input string) string {
	// HTML escape to prevent XSS
	sanitized := html.EscapeString(input)
	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)
	// Check for malicious patterns
	if middleware.CheckXSSPatterns(sanitized) || middleware.CheckSQLInjectionPatterns(sanitized) {
		return ""
	}
	return sanitized
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
