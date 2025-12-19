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
	Authenticate(ctx context.Context, identifier, password string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*dto.UserResponse, error)
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

	existingByUsername, err := s.userRepo.FindByUsername(ctx, req.Username)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}
	if existingByUsername != nil {
		return nil, errors.New("user with this username already exists")
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
		Username:  req.Username,
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
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		Confirmed: user.Confirmed,
		CreatedAt: user.CreatedAt,
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

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (s *userService) GetByID(ctx context.Context, id string) (*dto.UserResponse, error) {
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &dto.UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		LastName:  user.LastName,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		Confirmed: user.Confirmed,
		CreatedAt: user.CreatedAt,
	}, nil
}
