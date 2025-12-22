package handler

import (
	"net/http"

	"github.com/annazecevic/content-service/domain"
	"github.com/annazecevic/content-service/dto"
	"github.com/annazecevic/content-service/service"
	"github.com/gin-gonic/gin"
)

type ContentHandler struct{
    svc service.ContentService
}

func NewContentHandler(svc service.ContentService) *ContentHandler { return &ContentHandler{svc: svc} }

func (h *ContentHandler) RegisterRoutes(r *gin.Engine) {
    g := r.Group("/content")
    g.POST("/genres", h.CreateGenre)
    g.GET("/genres", h.ListGenres)

    g.POST("/artists", h.CreateArtist)
    g.GET("/artists", h.ListArtists)

    g.POST("/albums", h.CreateAlbum)
    g.GET("/albums", h.ListAlbums)

    g.POST("/tracks", h.CreateTrack)
    g.GET("/tracks", h.ListTracks)
}

func (h *ContentHandler) CreateGenre(c *gin.Context) {
    var req dto.CreateGenreRequest
    if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	role := c.GetHeader("X-User-Role")
    if role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: admin only"})
        return
    }
    g := &domain.Genre{ID: req.ID, Name: req.Name, Desc: req.Desc}
    if err := h.svc.CreateGenre(c.Request.Context(), g); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusCreated, g)
}

func (h *ContentHandler) ListGenres(c *gin.Context) {
    out, err := h.svc.ListGenres(c.Request.Context())
    if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) CreateArtist(c *gin.Context) {
    var req dto.CreateArtistRequest
    if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
    role := c.GetHeader("X-User-Role")
    if role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: admin only"})
        return
    }
    a := &domain.Artist{ID: req.ID, Name: req.Name, Genres: req.Genres, About: req.About}
    if err := h.svc.CreateArtist(c.Request.Context(), a); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusCreated, a)
}

func (h *ContentHandler) ListArtists(c *gin.Context) {
    out, err := h.svc.ListArtists(c.Request.Context())
    if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) CreateAlbum(c *gin.Context) {
    var req dto.CreateAlbumRequest
    if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
    role := c.GetHeader("X-User-Role")
    if role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: admin only"})
        return
    }
    al := &domain.Album{ID: req.ID, Title: req.Title, Released: req.Released, Genre: req.Genre, ArtistIDs: req.ArtistIDs}
    if err := h.svc.CreateAlbum(c.Request.Context(), al); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusCreated, al)
}

func (h *ContentHandler) ListAlbums(c *gin.Context) {
    out, err := h.svc.ListAlbums(c.Request.Context())
    if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusOK, out)
}

func (h *ContentHandler) CreateTrack(c *gin.Context) {
    var req dto.CreateTrackRequest
    if err := c.ShouldBindJSON(&req); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
    role := c.GetHeader("X-User-Role")
    if role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: admin only"})
        return
    }
    t := &domain.Track{ID: req.ID, Title: req.Title, Duration: req.Duration, Genre: req.Genre, AlbumID: req.AlbumID, ArtistIDs: req.ArtistIDs}
    if err := h.svc.CreateTrack(c.Request.Context(), t); err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusCreated, t)
}

func (h *ContentHandler) ListTracks(c *gin.Context) {
    out, err := h.svc.ListTracks(c.Request.Context())
    if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
    c.JSON(http.StatusOK, out)
}
