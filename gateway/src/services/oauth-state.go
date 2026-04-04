package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const oauthStatePrefix = "gw:oauth_state:"

type OAuthState struct {
	AuthSessionID string `json:"auth_session_id"`
	CodeVerifier  string `json:"code_verifier"`
	AccessToken   string `json:"access_token,omitempty"`
}

type OAuthStateService struct {
	rdb *redis.Client
}

func NewOAuthStateService(rdb *redis.Client) *OAuthStateService {
	return &OAuthStateService{rdb: rdb}
}

func (s *OAuthStateService) Store(ctx context.Context, entry OAuthState, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth_state rand: %w", err)
	}

	state := hex.EncodeToString(b)
	data, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("oauth_state marshal: %w", err)
	}

	if err := s.rdb.Set(ctx, oauthStatePrefix+state, data, ttl).Err(); err != nil {
		return "", fmt.Errorf("oauth_state store: %w", err)
	}

	return state, nil
}

func (s *OAuthStateService) Consume(ctx context.Context, state string) (*OAuthState, error) {
	data, err := s.rdb.GetDel(ctx, oauthStatePrefix+state).Bytes()
	if err != nil {
		return nil, fmt.Errorf("oauth_state consume: %w", err)
	}

	var entry OAuthState
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("oauth_state unmarshal: %w", err)
	}

	return &entry, nil
}
