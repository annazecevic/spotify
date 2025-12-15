package service

import (
	"context"
	"errors"
	"time"

	"github.com/annazecevic/user-service/domain"
	"github.com/annazecevic/user-service/dto"
	"github.com/annazecevic/user-service/repository"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	Register(ctx context.Context, req *dto.RegisterUserRequest) (*dto.UserResponse, error)
}

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) Register(ctx context.Context, req *dto.RegisterUserRequest) (*dto.UserResponse, error) {
	existingUser, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	user := &domain.User{
		ID:        uuid.New().String(),
		Name:      req.Name,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  string(hashedPassword),
		Confirmed: false,
		CreatedAt: now,
		UpdatedAt: now,
		Role:      "user",
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return &dto.UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		LastName:  user.LastName,
		Email:     user.Email,
		Role:      user.Role,
		Confirmed: user.Confirmed,
		CreatedAt: user.CreatedAt,
	}, nil
}
