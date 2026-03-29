package main

import (
	"openauth/router"
	"openauth/utils"
	casbinutil "openauth/utils/casbin"
)

func main() {
	utils.LoadConfig()
	utils.InitValidator()
	utils.DatabaseConnect()
	casbinutil.Init()
	utils.RedisConnect()
	utils.NatsConnect()

	router.Setup()

	select {}
}
