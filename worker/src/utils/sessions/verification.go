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
	prefixVerificationSession = "verification_session"
	prefixVerificationCode    = "verification_code"
	prefixVerificationResend  = "verification_resend"
)

var ErrResendTooSoon = errors.New("resend too soon")

var verifyVerificationScript = redis.NewScript(`
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

func CreateVerificationSession(ctx context.Context, userID uuid.UUID, credType, credValue string, ttl time.Duration) (string, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s:%s", prefixVerificationSession, sessionID)

	if err := utils.Redis.HSet(ctx, key, map[string]any{
		"user_id":    userID.String(),
		"cred_type":  credType,
		"cred_value": credValue,
	}).Err(); err != nil {
		return "", err
	}

	if err := utils.Redis.Expire(ctx, key, ttl).Err(); err != nil {
		return "", err
	}

	return sessionID, nil
}

func GetVerificationSession(ctx context.Context, sessionID string) (uuid.UUID, string, string, error) {
	key := fmt.Sprintf("%s:%s", prefixVerificationSession, sessionID)

	data, err := utils.Redis.HGetAll(ctx, key).Result()
	if err != nil {
		return uuid.Nil, "", "", err
	}

	if len(data) == 0 {
		return uuid.Nil, "", "", errors.New("session not found")
	}

	userID, err := uuid.Parse(data["user_id"])
	if err != nil {
		return uuid.Nil, "", "", err
	}

	return userID, data["cred_type"], data["cred_value"], nil
}

func DeleteVerificationSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("%s:%s", prefixVerificationSession, sessionID)
	return utils.Redis.Del(ctx, key).Err()
}

func StoreVerificationCode(ctx context.Context, sessionID string, userID uuid.UUID, code, credType string, ttl time.Duration) error {
	key := fmt.Sprintf("%s:%s", prefixVerificationCode, sessionID)

	if err := utils.Redis.HSet(ctx, key, map[string]any{
		"code":     code,
		"user_id":  userID.String(),
		"type":     credType,
		"attempts": 0,
	}).Err(); err != nil {
		return err
	}

	return utils.Redis.Expire(ctx, key, ttl).Err()
}

func VerifyVerificationCode(ctx context.Context, sessionID, input string) (bool, error) {
	key := fmt.Sprintf("%s:%s", prefixVerificationCode, sessionID)

	result, err := verifyVerificationScript.Run(ctx, utils.Redis, []string{key}, input, utils.Config.Verification.MaxAttempts).Int()
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

func DeleteVerificationCode(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("%s:%s", prefixVerificationCode, sessionID)
	return utils.Redis.Del(ctx, key).Err()
}

func CheckAndSetResendInterval(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("%s:%s", prefixVerificationResend, sessionID)
	ttl := time.Duration(utils.Config.Verification.ResendInterval) * time.Second

	set, err := utils.Redis.SetNX(ctx, key, 1, ttl).Result()
	if err != nil {
		return err
	}

	if !set {
		return ErrResendTooSoon
	}

	return nil
}
