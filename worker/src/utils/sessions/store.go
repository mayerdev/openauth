package sessions

import (
	"context"
	"fmt"
	"time"

	"openauth/worker/utils"

	"github.com/google/uuid"
)

const prefixSession = "session"

func SaveSession(ctx context.Context, sessionID string, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("%s:%s", prefixSession, sessionID)
	return utils.Redis.Set(ctx, key, userID.String(), ttl).Err()
}

func SessionExists(ctx context.Context, sessionID string) (bool, error) {
	key := fmt.Sprintf("%s:%s", prefixSession, sessionID)
	n, err := utils.Redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func DeleteSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("%s:%s", prefixSession, sessionID)
	return utils.Redis.Del(ctx, key).Err()
}
