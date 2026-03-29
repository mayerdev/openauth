package utils

import (
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
)

var Nats *nats.Conn

func NatsConnect() {
	url := fmt.Sprintf("nats://%s:%d", Config.NATS.Host, Config.NATS.Port)

	var err error
	Nats, err = nats.Connect(url)
	if err != nil {
		panic(err)
	}

	log.Info().Str("host", Config.NATS.Host).Int("port", Config.NATS.Port).Msg("NATS connected")
}
