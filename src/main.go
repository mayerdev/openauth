package main

import (
	"os"
	"time"

	"openauth/router"
	"openauth/utils"
	casbinutil "openauth/utils/casbin"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	utils.LoadConfig()
	utils.InitValidator()
	utils.DatabaseConnect()
	casbinutil.Init()
	utils.RedisConnect()
	utils.NatsConnect()

	router.Setup()

	log.Info().Msg("OpenAuth started")

	select {}
}
