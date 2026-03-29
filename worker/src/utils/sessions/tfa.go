package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"openauth/worker/utils"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	prefixTfaSession = "tfa_session"
	prefixTfaCode    = "tfa_code"
)

var ErrMaxAttempts = errors.New("max attempts exceeded")

const maxTfaAttempts = 5

var verifyTfaScript = redis.NewScript(`
local key = KEYS[1]
local input = ARGV[1]
local limit = tonumber(ARGV[2])

if redis.call('EXISTS', key) == 0 then
  return -1
end

local attempts = redis.call('HINCRBY', key, 'attempts', 1)
if attempts > limit then
  return 0
end

local stored = redis.call('HGET', key, 'code')
if stored == input then
  return 1
end

return 2
`)

func CreateTfaSession(ctx context.Context, userID uuid.UUID, method string, ttl time.Duration) (string, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s:%s", prefixTfaSession, sessionID)

	if err := utils.Redis.HSet(ctx, key, map[string]interface{}{
		"user_id": userID.String(),
		"method":  method,
	}).Err(); err != nil {
		return "", err
	}

	if err := utils.Redis.Expire(ctx, key, ttl).Err(); err != nil {
		return "", err
	}

	return sessionID, nil
}

func GetTfaSession(ctx context.Context, sessionID string) (uuid.UUID, string, error) {
	key := fmt.Sprintf("%s:%s", prefixTfaSession, sessionID)

	data, err := utils.Redis.HGetAll(ctx, key).Result()
	if err != nil {
		return uuid.Nil, "", err
	}

	if len(data) == 0 {
		return uuid.Nil, "", errors.New("session not found")
	}

	userID, err := uuid.Parse(data["user_id"])
	if err != nil {
		return uuid.Nil, "", err
	}

	return userID, data["method"], nil
}

func DeleteTfaSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("%s:%s", prefixTfaSession, sessionID)

	return utils.Redis.Del(ctx, key).Err()
}

func StoreTfaCode(ctx context.Context, sessionID string, userID uuid.UUID, code, method string, ttl time.Duration) error {
	key := fmt.Sprintf("%s:%s", prefixTfaCode, sessionID)

	if err := utils.Redis.HSet(ctx, key, map[string]interface{}{
		"code":     code,
		"user_id":  userID.String(),
		"method":   method,
		"attempts": 0,
	}).Err(); err != nil {
		return err
	}

	return utils.Redis.Expire(ctx, key, ttl).Err()
}

func VerifyTfaCode(ctx context.Context, sessionID, input string) (bool, error) {
	key := fmt.Sprintf("%s:%s", prefixTfaCode, sessionID)

	result, err := verifyTfaScript.Run(ctx, utils.Redis, []string{key}, input, maxTfaAttempts).Int()
	if err != nil {
		return false, err
	}

	switch result {
	case 1:
		return true, nil
	case 0:
		return false, ErrMaxAttempts
	default:
		return false, nil
	}
}
