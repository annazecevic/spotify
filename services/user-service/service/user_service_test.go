package service

import (
	"context"
	"testing"

	"github.com/annazecevic/user-service/domain"
	"github.com/annazecevic/user-service/dto"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type mockRepo struct {
    FindByEmailResp     *domain.User
    FindByEmailErr      error
    FindByUsernameResp  *domain.User
    FindByUsernameErr   error
    CreateErr           error
    FindByIDResp        *domain.User
    FindByIDErr         error
}

func (m *mockRepo) Create(ctx context.Context, user *domain.User) error {
    return m.CreateErr
}
func (m *mockRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
    if m.FindByEmailErr != nil {
        return nil, m.FindByEmailErr
    }
    if m.FindByEmailResp != nil {
        return m.FindByEmailResp, nil
    }
    return nil, mongo.ErrNoDocuments
}
func (m *mockRepo) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
    if m.FindByUsernameErr != nil {
        return nil, m.FindByUsernameErr
    }
    if m.FindByUsernameResp != nil {
        return m.FindByUsernameResp, nil
    }
    return nil, mongo.ErrNoDocuments
}
func (m *mockRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
    if m.FindByIDErr != nil {
        return nil, m.FindByIDErr
    }
    if m.FindByIDResp != nil {
        return m.FindByIDResp, nil
    }
    return nil, mongo.ErrNoDocuments
}

func TestAuthenticateByEmailSuccess(t *testing.T) {
    pw := "secret123"
    hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
    user := &domain.User{ID: "1", Email: "a@b.com", Password: string(hashed)}

    repo := &mockRepo{FindByEmailResp: user}
    svc := NewUserService(repo)

    got, err := svc.Authenticate(context.Background(), "a@b.com", pw)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got == nil || got.ID != user.ID {
        t.Fatalf("expected user id %s, got %v", user.ID, got)
    }
}

func TestAuthenticateByUsernameSuccess(t *testing.T) {
    pw := "mypw"
    hashed, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
    user := &domain.User{ID: "2", Username: "alice", Password: string(hashed)}

    repo := &mockRepo{FindByEmailErr: mongo.ErrNoDocuments, FindByUsernameResp: user}
    svc := NewUserService(repo)

    got, err := svc.Authenticate(context.Background(), "alice", pw)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got == nil || got.ID != user.ID {
        t.Fatalf("expected user id %s, got %v", user.ID, got)
    }
}

func TestAuthenticateInvalidPassword(t *testing.T) {
    hashed, _ := bcrypt.GenerateFromPassword([]byte("rightpw"), bcrypt.DefaultCost)
    user := &domain.User{ID: "3", Email: "x@y.com", Password: string(hashed)}

    repo := &mockRepo{FindByEmailResp: user}
    svc := NewUserService(repo)

    _, err := svc.Authenticate(context.Background(), "x@y.com", "wrongpw")
    if err == nil {
        t.Fatalf("expected invalid credentials error, got nil")
    }
}

func TestRegisterDuplicateEmail(t *testing.T) {
    repo := &mockRepo{FindByEmailResp: &domain.User{ID: "9"}}
    svc := NewUserService(repo)

    _, err := svc.Register(context.Background(), &dto.RegisterUserRequest{})
    if err == nil {
        t.Fatalf("expected error due to duplicate email, got nil")
    }
}

func TestRegisterDuplicateUsername(t *testing.T) {
    repo := &mockRepo{FindByEmailErr: mongo.ErrNoDocuments, FindByUsernameResp: &domain.User{ID: "10"}}
    svc := NewUserService(repo)

    _, err := svc.Register(context.Background(), &dto.RegisterUserRequest{})
    if err == nil {
        t.Fatalf("expected error due to duplicate username, got nil")
    }
}
