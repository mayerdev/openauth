package utils

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var Redis *redis.Client

func RedisConnect() {
	addr := fmt.Sprintf("%s:%d", Config.Redis.Host, Config.Redis.Port)
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}

	Redis = client

	log.Info().Str("host", Config.Redis.Host).Int("port", Config.Redis.Port).Msg("Redis connected")
}
