package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/annazecevic/user-service/domain"
	"github.com/annazecevic/user-service/dto"
	"github.com/annazecevic/user-service/logger"
	"github.com/annazecevic/user-service/repository"
	"github.com/annazecevic/user-service/utils"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Register(ctx context.Context, req *dto.RegisterUserRequest) (*dto.UserResponse, error)
	Authenticate(ctx context.Context, identifier, password string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*dto.UserResponse, error)
	ConfirmEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error
	UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, error)
	SendOTP(ctx context.Context, user *domain.User) error
	VerifyOTP(ctx context.Context, email, otpCode string) (*domain.User, error)
	RequestMagicLink(ctx context.Context, email string) error
	VerifyMagicLink(ctx context.Context, token string) (*domain.User, error)
}

type userService struct {
	userRepo     repository.UserRepository
	emailService utils.EmailService
}

func NewUserService(userRepo repository.UserRepository, emailService utils.EmailService) UserService {
	return &userService{
		userRepo:     userRepo,
		emailService: emailService,
	}
}

func (s *userService) Register(ctx context.Context, req *dto.RegisterUserRequest) (*dto.UserResponse, error) {
	// Input validation (2.18)
	if err := utils.ValidateUsername(req.Username); err != nil {
		return nil, err
	}

	if err := utils.ValidateName(req.Name); err != nil {
		return nil, fmt.Errorf("invalid first name: %w", err)
	}

	if err := utils.ValidateName(req.LastName); err != nil {
		return nil, fmt.Errorf("invalid last name: %w", err)
	}

	if err := utils.ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	if err := utils.ValidatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Sanitize inputs (2.18 - XSS protection)
	req.Name = utils.SanitizeInput(req.Name)
	req.LastName = utils.SanitizeInput(req.LastName)
	req.Username = utils.SanitizeInput(req.Username)
	req.Email = utils.SanitizeInput(req.Email)

	existingUser, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	existingByUsername, err := s.userRepo.FindByUsername(ctx, req.Username)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}
	if existingByUsername != nil {
		return nil, errors.New("user with this username already exists")
	}

	// DefaultCost = 10, which provides good security vs performance balance
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	confirmationToken := utils.GenerateConfirmationToken()
	tokenExpiration := time.Now().Add(24 * time.Hour).Unix()
	passwordExpiration := time.Now().AddDate(0, 0, 90).Unix()

	user := &domain.User{
		ID:                uuid.New().String(),
		Name:              req.Name,
		LastName:          req.LastName,
		Username:          req.Username,
		Email:             req.Email,
		Password:          string(hashedPassword),
		Confirmed:         false,
		ConfirmationToken: confirmationToken,
		TokenExpiresAt:    tokenExpiration,
		PasswordChangedAt: now,
		PasswordExpiresAt: passwordExpiration,
		CreatedAt:         now,
		UpdatedAt:         now,
		Role:              "user",
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	if err := s.emailService.SendConfirmationEmail(user.Email, user.Name, confirmationToken); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to send confirmation email", logger.Fields(
			"user_id", user.ID,
			"error", err.Error(),
		))
	}

	return &dto.UserResponse{
		ID:                user.ID,
		Name:              user.Name,
		LastName:          user.LastName,
		Username:          user.Username,
		Email:             user.Email,
		Role:              user.Role,
		Confirmed:         user.Confirmed,
		CreatedAt:         user.CreatedAt,
		PasswordExpiresAt: user.PasswordExpiresAt,
	}, nil
}

func (s *userService) Authenticate(ctx context.Context, identifier, password string) (*domain.User, error) {
	user, err := s.userRepo.FindByEmail(ctx, identifier)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			return nil, err
		}
		user, err = s.userRepo.FindByUsername(ctx, identifier)
		if err != nil {
			return nil, err
		}
	}

	if !user.Confirmed {
		return nil, errors.New("email not confirmed. Please check your email for confirmation link")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	if user.PasswordExpiresAt > 0 && time.Now().Unix() > user.PasswordExpiresAt {
		return nil, errors.New("password has expired. Please reset your password")
	}

	return user, nil
}

func (s *userService) GetByID(ctx context.Context, id string) (*dto.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &dto.UserResponse{
		ID:                user.ID,
		Name:              user.Name,
		LastName:          user.LastName,
		Username:          user.Username,
		Email:             user.Email,
		Role:              user.Role,
		Confirmed:         user.Confirmed,
		CreatedAt:         user.CreatedAt,
		PasswordExpiresAt: user.PasswordExpiresAt,
	}, nil
}

func (s *userService) ConfirmEmail(ctx context.Context, token string) error {
	user, err := s.userRepo.FindByConfirmationToken(ctx, token)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return errors.New("invalid confirmation token")
		}
		return err
	}

	if user.TokenExpiresAt > 0 && time.Now().Unix() > user.TokenExpiresAt {
		return errors.New("confirmation token has expired. Please request a new one")
	}

	if user.Confirmed {
		return errors.New("email already confirmed")
	}

	return s.userRepo.UpdateConfirmation(ctx, user.ID)
}

func (s *userService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	resetToken := utils.GenerateConfirmationToken()
	tokenExpiration := time.Now().Add(1 * time.Hour).Unix()

	user.PasswordResetToken = resetToken
	user.ResetTokenExpiresAt = tokenExpiration
	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	if err := s.emailService.SendPasswordResetEmail(user.Email, user.Name, resetToken); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to send password reset email", logger.Fields(
			"user_id", user.ID,
			"error", err.Error(),
		))
	}

	return nil
}

func (s *userService) ResetPassword(ctx context.Context, token, newPassword string) error {
	if err := utils.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	user, err := s.userRepo.FindByPasswordResetToken(ctx, token)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return errors.New("invalid or expired reset token")
		}
		return err
	}

	if user.ResetTokenExpiresAt > 0 && time.Now().Unix() > user.ResetTokenExpiresAt {
		return errors.New("reset token has expired. Please request a new password reset")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	user.Password = string(hashedPassword)
	user.PasswordResetToken = ""
	user.ResetTokenExpiresAt = 0
	user.PasswordChangedAt = now
	user.PasswordExpiresAt = time.Now().AddDate(0, 0, 60).Unix()
	user.UpdatedAt = now

	return s.userRepo.Update(ctx, user)
}

func (s *userService) SendOTP(ctx context.Context, user *domain.User) error {
	otpCode, err := utils.GenerateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	otpExpiresAt := time.Now().Add(10 * time.Minute).Unix()

	user.OTPCode = otpCode
	user.OTPExpiresAt = otpExpiresAt
	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	if err := s.emailService.SendOTPEmail(user.Email, user.Username, otpCode); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	return nil
}

func (s *userService) VerifyOTP(ctx context.Context, email, otpCode string) (*domain.User, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	if user.OTPCode == "" {
		return nil, errors.New("no OTP found. Please request a new one")
	}

	if time.Now().Unix() > user.OTPExpiresAt {
		return nil, errors.New("OTP has expired. Please request a new one")
	}

	if user.OTPCode != otpCode {
		return nil, errors.New("invalid OTP code")
	}

	user.OTPCode = ""
	user.OTPExpiresAt = 0
	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to clear OTP: %w", err)
	}

	return user, nil
}

func (s *userService) RequestMagicLink(ctx context.Context, email string) error {
	if err := utils.ValidateEmail(email); err != nil {
		return err
	}

	email = utils.SanitizeInput(email)

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	if !user.Confirmed {
		return errors.New("email not confirmed. Please confirm your email first")
	}

	magicLinkToken := utils.GenerateConfirmationToken()
	tokenExpiration := time.Now().Add(15 * time.Minute).Unix()

	user.MagicLinkToken = magicLinkToken
	user.MagicLinkExpiresAt = tokenExpiration
	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	if err := s.emailService.SendMagicLinkEmail(user.Email, user.Name, magicLinkToken); err != nil {
		logger.Warn(logger.EventGeneral, "Failed to send magic link email", logger.Fields(
			"user_id", user.ID,
			"error", err.Error(),
		))
	}

	return nil
}

func (s *userService) VerifyMagicLink(ctx context.Context, token string) (*domain.User, error) {
	user, err := s.userRepo.FindByMagicLinkToken(ctx, token)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("invalid or expired magic link")
		}
		return nil, err
	}

	if user.MagicLinkExpiresAt > 0 && time.Now().Unix() > user.MagicLinkExpiresAt {
		return nil, errors.New("magic link has expired. Please request a new one")
	}

	if !user.Confirmed {
		return nil, errors.New("email not confirmed")
	}

	if user.PasswordExpiresAt > 0 && time.Now().Unix() > user.PasswordExpiresAt {
		return nil, errors.New("password has expired. Please reset your password")
	}

	user.MagicLinkToken = ""
	user.MagicLinkExpiresAt = 0
	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to clear magic link token: %w", err)
	}

	return user, nil
}

func (s *userService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	if err := utils.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	user.Password = string(hashedPassword)
	user.PasswordChangedAt = now
	user.PasswordExpiresAt = time.Now().AddDate(0, 0, 90).Unix()
	user.UpdatedAt = now

	return s.userRepo.Update(ctx, user)
}

func (s *userService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	if req.Name != "" {
		if err := utils.ValidateName(req.Name); err != nil {
			return nil, fmt.Errorf("invalid first name: %w", err)
		}
		user.Name = utils.SanitizeInput(req.Name)
	}

	if req.LastName != "" {
		if err := utils.ValidateName(req.LastName); err != nil {
			return nil, fmt.Errorf("invalid last name: %w", err)
		}
		user.LastName = utils.SanitizeInput(req.LastName)
	}

	if req.Username != "" {
		if err := utils.ValidateUsername(req.Username); err != nil {
			return nil, err
		}
		existingUser, err := s.userRepo.FindByUsername(ctx, req.Username)
		if err != nil && err != mongo.ErrNoDocuments {
			return nil, err
		}
		if existingUser != nil && existingUser.ID != userID {
			return nil, errors.New("username is already taken")
		}
		user.Username = utils.SanitizeInput(req.Username)
	}

	user.UpdatedAt = time.Now().Unix()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &dto.UserResponse{
		ID:                user.ID,
		Name:              user.Name,
		LastName:          user.LastName,
		Username:          user.Username,
		Email:             user.Email,
		Role:              user.Role,
		Confirmed:         user.Confirmed,
		CreatedAt:         user.CreatedAt,
		PasswordExpiresAt: user.PasswordExpiresAt,
	}, nil
}
