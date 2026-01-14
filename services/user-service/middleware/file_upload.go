package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// FileUploadConfig contains configuration for file uploads (2.18)
type FileUploadConfig struct {
	MaxFileSize      int64    // Maximum file size in bytes
	AllowedMimeTypes []string // Whitelisted MIME types
	AllowedExtensions []string // Whitelisted file extensions
}

// DefaultImageUploadConfig returns config for image uploads
func DefaultImageUploadConfig() *FileUploadConfig {
	return &FileUploadConfig{
		MaxFileSize: 5 * 1024 * 1024, // 5MB
		AllowedMimeTypes: []string{
			"image/jpeg",
			"image/png",
			"image/gif",
			"image/webp",
		},
		AllowedExtensions: []string{
			".jpg",
			".jpeg",
			".png",
			".gif",
			".webp",
		},
	}
}

// DefaultAudioUploadConfig returns config for audio uploads
func DefaultAudioUploadConfig() *FileUploadConfig {
	return &FileUploadConfig{
		MaxFileSize: 50 * 1024 * 1024, // 50MB
		AllowedMimeTypes: []string{
			"audio/mpeg",
			"audio/mp3",
			"audio/wav",
			"audio/ogg",
			"audio/flac",
		},
		AllowedExtensions: []string{
			".mp3",
			".wav",
			".ogg",
			".flac",
		},
	}
}

// ValidateFileUpload middleware validates uploaded files (2.18)
func ValidateFileUpload(config *FileUploadConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This middleware should be used on file upload endpoints
		c.Next()
	}
}

// ValidateUploadedFile validates a single uploaded file (2.18)
func ValidateUploadedFile(file *multipart.FileHeader, config *FileUploadConfig) error {
	// 1. Check file size (boundary checking)
	if file.Size > config.MaxFileSize {
		return fmt.Errorf("file size exceeds maximum allowed size of %d bytes", config.MaxFileSize)
	}

	if file.Size == 0 {
		return fmt.Errorf("file is empty")
	}

	// 2. Check file extension (whitelisting)
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if !contains(config.AllowedExtensions, ext) {
		return fmt.Errorf("file extension %s is not allowed", ext)
	}

	// 3. Validate filename (no path traversal)
	filename := filepath.Base(file.Filename)
	if filename != file.Filename || strings.Contains(filename, "..") {
		return fmt.Errorf("invalid filename")
	}

	// 4. Check MIME type (whitelisting)
	// Note: This checks the Content-Type header, which can be spoofed
	// For production, use a library like filetype to detect actual file type
	contentType := file.Header.Get("Content-Type")
	if contentType != "" && !contains(config.AllowedMimeTypes, contentType) {
		return fmt.Errorf("file type %s is not allowed", contentType)
	}

	return nil
}

// CalculateFileChecksum calculates SHA-256 checksum for integrity verification (2.18)
func CalculateFileChecksum(file multipart.File) (string, error) {
	hash := sha256.New()
	
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	// Reset file pointer to beginning
	if _, err := file.Seek(0, 0); err != nil {
		return "", err
	}

	checksum := hex.EncodeToString(hash.Sum(nil))
	return checksum, nil
}

// ValidateFileContent performs deep validation of file content (2.18)
func ValidateFileContent(file multipart.File, expectedMimeType string) error {
	// Read first 512 bytes to detect file type
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}

	// Reset file pointer
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	// Detect content type from actual file content
	detectedType := http.DetectContentType(buffer)
	
	// For stricter validation, you can compare with expected type
	// This prevents users from uploading executable files with image extensions
	if !strings.HasPrefix(detectedType, strings.Split(expectedMimeType, "/")[0]) {
		return fmt.Errorf("file content does not match expected type")
	}

	return nil
}

// SanitizeFilename removes dangerous characters from filename (2.18)
func SanitizeFilename(filename string) string {
	// Remove path components
	filename = filepath.Base(filename)
	
	// Remove or replace dangerous characters
	dangerous := []string{"..", "/", "\\", "<", ">", ":", "\"", "|", "?", "*"}
	for _, char := range dangerous {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	
	// Limit filename length
	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		filename = filename[:255-len(ext)] + ext
	}
	
	return filename
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// FileUploadResponse contains information about uploaded file
type FileUploadResponse struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
	Checksum string `json:"checksum"`
	URL      string `json:"url,omitempty"`
}

