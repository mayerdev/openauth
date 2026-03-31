package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const authSessionPrefix = "gw:auth_session:"

type AuthSession struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
}

type AuthSessionService struct {
	rdb *redis.Client
}

func NewAuthSessionService(rdb *redis.Client) *AuthSessionService {
	return &AuthSessionService{rdb: rdb}
}

func (s *AuthSessionService) Create(ctx context.Context, sess AuthSession, ttl time.Duration) (string, error) {
	id := uuid.NewString()
	data, err := json.Marshal(sess)
	if err != nil {
		return "", fmt.Errorf("auth_session marshal: %w", err)
	}

	if err := s.rdb.Set(ctx, authSessionPrefix+id, data, ttl).Err(); err != nil {
		return "", fmt.Errorf("auth_session store: %w", err)
	}

	return id, nil
}

func (s *AuthSessionService) Get(ctx context.Context, id string) (*AuthSession, error) {
	data, err := s.rdb.Get(ctx, authSessionPrefix+id).Bytes()
	if err != nil {
		return nil, fmt.Errorf("auth_session get: %w", err)
	}

	var sess AuthSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("auth_session unmarshal: %w", err)
	}

	return &sess, nil
}

func (s *AuthSessionService) Delete(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, authSessionPrefix+id).Err()
}
