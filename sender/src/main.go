package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatal().Err(err).Msg("nats connect")
	}
	defer nc.Close()

	log.Info().Str("url", natsURL).Msg("connected to NATS")

	nc.QueueSubscribe("openauth.sender.email", "senders", func(msg *nats.Msg) {
		var payload map[string]string
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Error().Err(err).Msg("email: failed to decode message")
			return
		}
		log.Info().Str("to", payload["to"]).Str("code", payload["code"]).Msg("email")
	})

	nc.QueueSubscribe("openauth.sender.sms", "senders", func(msg *nats.Msg) {
		var payload map[string]string
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Error().Err(err).Msg("sms: failed to decode message")
			return
		}
		log.Info().Str("to", payload["to"]).Str("code", payload["code"]).Msg("sms")
	})

	nc.Flush()

	select {}
}
