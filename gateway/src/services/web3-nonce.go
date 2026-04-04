package services

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	web3NoncePrefix     = "gw:web3_nonce:"
	web3NonceLinkPrefix = "gw:web3_nonce_link:"
)

type Web3NonceService struct {
	rdb *redis.Client
}

func NewWeb3NonceService(rdb *redis.Client) *Web3NonceService {
	return &Web3NonceService{rdb: rdb}
}

func (s *Web3NonceService) Store(ctx context.Context, authSessionID, nonce string, ttl time.Duration) error {
	return s.rdb.Set(ctx, web3NoncePrefix+authSessionID, nonce, ttl).Err()
}

func (s *Web3NonceService) Consume(ctx context.Context, authSessionID string) (string, error) {
	nonce, err := s.rdb.GetDel(ctx, web3NoncePrefix+authSessionID).Result()
	if err != nil {
		return "", fmt.Errorf("web3_nonce consume: %w", err)
	}

	return nonce, nil
}

func (s *Web3NonceService) StoreForLink(ctx context.Context, accessToken, nonce string, ttl time.Duration) error {
	return s.rdb.Set(ctx, web3NonceLinkPrefix+accessToken, nonce, ttl).Err()
}

func (s *Web3NonceService) ConsumeForLink(ctx context.Context, accessToken string) (string, error) {
	nonce, err := s.rdb.GetDel(ctx, web3NonceLinkPrefix+accessToken).Result()
	if err != nil {
		return "", fmt.Errorf("web3_nonce_link consume: %w", err)
	}

	return nonce, nil
}
