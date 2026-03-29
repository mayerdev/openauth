package utils

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client

func RedisConnect() {
	Redis = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", Config.Redis.Host, Config.Redis.Port),
	})

	if err := Redis.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}
}
