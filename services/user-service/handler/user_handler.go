package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/annazecevic/user-service/dto"
	"github.com/annazecevic/user-service/logger"
	"github.com/annazecevic/user-service/service"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type UserHandler struct {
	userService service.UserService
	jwtSecret   string
}

func NewUserHandler(userService service.UserService, jwtSecret string) *UserHandler {
	return &UserHandler{
		userService: userService,
		jwtSecret:   jwtSecret,
	}
}

func (h *UserHandler) Register(c *gin.Context) {
	var req dto.RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid registration request", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.Register(c.Request.Context(), &req)
	if err != nil {
		logger.Warn(logger.EventGeneral, "Registration failed", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Info(logger.EventGeneral, "New user registered", logger.Fields(
		"user_id", user.ID,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusCreated, user)
}

func (h *UserHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid login request body", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.Authenticate(c.Request.Context(), req.Identifier, req.Password)
	if err != nil {
		logger.Security(logger.EventLoginFailure, "Login failed", logger.Fields(
			"identifier", req.Identifier,
			"ip", c.ClientIP(),
			"reason", err.Error(),
		))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.SendOTP(c.Request.Context(), user); err != nil {
		logger.Error(logger.EventGeneral, "Failed to send OTP during login", logger.Fields(
			"user_id", user.ID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send OTP: " + err.Error()})
		return
	}

	logger.Security(logger.EventLoginSuccess, "Credentials verified, OTP sent", logger.Fields(
		"user_id", user.ID,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent to your email. Please verify to complete login.",
		"email":   user.Email,
	})
}

// ValidateToken is the nginx auth_request endpoint - validates JWT and sets user headers
func (h *UserHandler) ValidateToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		logger.Security(logger.EventInvalidToken, "Missing authorization header", logger.Fields("ip", c.ClientIP()))
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		logger.Security(logger.EventInvalidToken, "Malformed authorization header", logger.Fields("ip", c.ClientIP()))
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	tokenString := parts[1]

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(h.jwtSecret), nil
	})
	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			logger.Security(logger.EventExpiredToken, "Access attempt with expired token", logger.Fields("ip", c.ClientIP()))
		} else {
			logger.Security(logger.EventInvalidToken, "Access attempt with invalid token", logger.Fields("ip", c.ClientIP()))
		}
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logger.Security(logger.EventInvalidToken, "Token has invalid claims structure", logger.Fields("ip", c.ClientIP()))
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		logger.Security(logger.EventInvalidToken, "Token missing user ID claim", logger.Fields("ip", c.ClientIP()))
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.Header("X-User-ID", sub)
	if role, ok := claims["role"].(string); ok && role != "" {
		c.Header("X-User-Role", role)
	}

	c.JSON(http.StatusOK, gin.H{"user_id": sub})
}

func (h *UserHandler) Me(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 {
				tokenString := parts[1]
				token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
					if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method")
					}
					return []byte(h.jwtSecret), nil
				})
				if err == nil && token.Valid {
					if claims, ok := token.Claims.(jwt.MapClaims); ok {
						if sub, ok := claims["sub"].(string); ok && sub != "" {
							userID = sub
						}
					}
				}
			}
		}
	}

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user id"})
		return
	}
	userResp, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, userResp)
}

func (h *UserHandler) ConfirmEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		var req dto.ConfirmEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
			return
		}
		token = req.Token
	}

	if err := h.userService.ConfirmEmail(c.Request.Context(), token); err != nil {
		logger.Warn(logger.EventGeneral, "Email confirmation failed", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info(logger.EventGeneral, "Email confirmed successfully", logger.Fields("ip", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"message": "Email confirmed successfully. You can now login."})
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req dto.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid change password request", logger.Fields(
			"user_id", userID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		logger.Security(logger.EventLoginFailure, "Password change failed", logger.Fields(
			"user_id", userID,
			"ip", c.ClientIP(),
			"reason", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info(logger.EventGeneral, "Password changed successfully", logger.Fields(
		"user_id", userID,
		"ip", c.ClientIP(),
	))
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req dto.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid update profile request", logger.Fields(
			"user_id", userID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.UpdateProfile(c.Request.Context(), userID, &req)
	if err != nil {
		logger.Warn(logger.EventValidationFailure, "Profile update failed", logger.Fields(
			"user_id", userID,
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) RequestPasswordReset(c *gin.Context) {
	var req dto.RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid password reset request", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.RequestPasswordReset(c.Request.Context(), req.Email); err != nil {
		logger.Error(logger.EventGeneral, "Password reset request processing failed", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password reset request"})
		return
	}

	// Ne logujemo email - izbegavamo otkrivanje da li nalog postoji
	logger.Info(logger.EventGeneral, "Password reset requested", logger.Fields("ip", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
}

func (h *UserHandler) ResetPassword(c *gin.Context) {
	var req dto.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid reset password request", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		logger.Security(logger.EventGeneral, "Password reset failed", logger.Fields(
			"ip", c.ClientIP(),
			"reason", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info(logger.EventGeneral, "Password reset completed", logger.Fields("ip", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully. You can now login with your new password."})
}

func (h *UserHandler) VerifyOTP(c *gin.Context) {
	var req dto.VerifyOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid OTP request body", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userService.VerifyOTP(c.Request.Context(), req.Email, req.OTP)
	if err != nil {
		logger.Security(logger.EventLoginFailure, "OTP verification failed", logger.Fields(
			"email", req.Email,
			"ip", c.ClientIP(),
			"reason", err.Error(),
		))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(h.jwtSecret))
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to sign JWT after OTP verification", logger.Fields(
			"user_id", user.ID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	var passwordExpiresSoon bool
	var passwordExpiresInDays int
	if user.PasswordExpiresAt > 0 {
		now := time.Now().Unix()
		daysUntilExpiration := int((user.PasswordExpiresAt - now) / 86400)
		if daysUntilExpiration <= 7 && daysUntilExpiration >= 0 {
			passwordExpiresSoon = true
			passwordExpiresInDays = daysUntilExpiration
		}
	}

	logger.Security(logger.EventLoginSuccess, "Login completed via OTP", logger.Fields(
		"user_id", user.ID,
		"role", user.Role,
		"ip", c.ClientIP(),
	))

	c.JSON(http.StatusOK, dto.LoginResponse{
		Token: tokenString,
		User: &dto.UserResponse{
			ID:                user.ID,
			Name:              user.Name,
			LastName:          user.LastName,
			Username:          user.Username,
			Email:             user.Email,
			Role:              user.Role,
			Confirmed:         user.Confirmed,
			CreatedAt:         user.CreatedAt,
			PasswordExpiresAt: user.PasswordExpiresAt,
		},
		PasswordExpiresSoon:   passwordExpiresSoon,
		PasswordExpiresInDays: passwordExpiresInDays,
	})
}

func (h *UserHandler) RequestMagicLink(c *gin.Context) {
	var req dto.RequestMagicLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn(logger.EventValidationFailure, "Invalid magic link request", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.userService.RequestMagicLink(c.Request.Context(), req.Email); err != nil {
		logger.Error(logger.EventGeneral, "Magic link request processing failed", logger.Fields(
			"ip", c.ClientIP(),
			"error", err.Error(),
		))
		c.JSON(http.StatusOK, gin.H{"message": "If an account with that email exists, a magic link has been sent."})
		return
	}

	logger.Info(logger.EventGeneral, "Magic link requested", logger.Fields("ip", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"message": "If an account with that email exists, a magic link has been sent."})
}

func (h *UserHandler) VerifyMagicLink(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		var req dto.VerifyMagicLinkRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
			return
		}
		token = req.Token
	}

	user, err := h.userService.VerifyMagicLink(c.Request.Context(), token)
	if err != nil {
		logger.Security(logger.EventLoginFailure, "Magic link verification failed", logger.Fields(
			"ip", c.ClientIP(),
			"reason", err.Error(),
		))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte(h.jwtSecret))
	if err != nil {
		logger.Error(logger.EventGeneral, "Failed to sign JWT after magic link verification", logger.Fields(
			"user_id", user.ID,
			"error", err.Error(),
		))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}

	var passwordExpiresSoon bool
	var passwordExpiresInDays int
	if user.PasswordExpiresAt > 0 {
		now := time.Now().Unix()
		daysUntilExpiration := int((user.PasswordExpiresAt - now) / 86400)
		if daysUntilExpiration <= 7 && daysUntilExpiration >= 0 {
			passwordExpiresSoon = true
			passwordExpiresInDays = daysUntilExpiration
		}
	}

	logger.Security(logger.EventLoginSuccess, "Login completed via magic link", logger.Fields(
		"user_id", user.ID,
		"role", user.Role,
		"ip", c.ClientIP(),
	))

	c.JSON(http.StatusOK, dto.LoginResponse{
		Token: tokenString,
		User: &dto.UserResponse{
			ID:                user.ID,
			Name:              user.Name,
			LastName:          user.LastName,
			Username:          user.Username,
			Email:             user.Email,
			Role:              user.Role,
			Confirmed:         user.Confirmed,
			CreatedAt:         user.CreatedAt,
			PasswordExpiresAt: user.PasswordExpiresAt,
		},
		PasswordExpiresSoon:   passwordExpiresSoon,
		PasswordExpiresInDays: passwordExpiresInDays,
	})
}
