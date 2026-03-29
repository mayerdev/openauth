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

const authCodePrefix = "gw:auth_code:"

type AuthCodeEntry struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
}

type AuthCodeService struct {
	rdb *redis.Client
}

func NewAuthCodeService(rdb *redis.Client) *AuthCodeService {
	return &AuthCodeService{rdb: rdb}
}

func (s *AuthCodeService) Create(ctx context.Context, entry AuthCodeEntry, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth_code rand: %w", err)
	}

	code := hex.EncodeToString(b)
	data, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("auth_code marshal: %w", err)
	}

	if err := s.rdb.Set(ctx, authCodePrefix+code, data, ttl).Err(); err != nil {
		return "", fmt.Errorf("auth_code store: %w", err)
	}

	return code, nil
}

func (s *AuthCodeService) Consume(ctx context.Context, code string) (*AuthCodeEntry, error) {
	data, err := s.rdb.GetDel(ctx, authCodePrefix+code).Bytes()
	if err != nil {
		return nil, fmt.Errorf("auth_code consume: %w", err)
	}

	var entry AuthCodeEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("auth_code unmarshal: %w", err)
	}

	return &entry, nil
}
