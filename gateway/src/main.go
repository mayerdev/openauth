package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"openauth/gateway/router"
	"openauth/gateway/utils"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	utils.LoadConfig()
	utils.RedisConnect()
	utils.NatsConnect()

	app := router.Setup()

	addr := fmt.Sprintf(":%d", utils.Config.Server.Port)
	log.Info().Str("addr", addr).Msg("gateway starting")
	if err := app.Listen(addr); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}
