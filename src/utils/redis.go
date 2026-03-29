package utils

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var Redis *redis.Client

func RedisConnect() {
	Redis = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", Config.Redis.Host, Config.Redis.Port),
	})

	if err := Redis.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}

	log.Info().
		Str("host", Config.Redis.Host).
		Int("port", Config.Redis.Port).
		Msg("Redis connected")
}
