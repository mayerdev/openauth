package router

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"openauth/gateway/federation"
	oauth2provider "openauth/gateway/federation/oauth2"
	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"
)

func Setup() *fiber.App {
	app := fiber.New(fiber.Config{AppName: "openauth-gateway"})

	worker := transport.NewWorkerClient(utils.Nats, 10*time.Second)
	sessions := services.NewAuthSessionService(utils.Redis)
	codes := services.NewAuthCodeService(utils.Redis)

	providers := []federation.Provider{
		oauth2provider.NewProvider(worker, sessions, codes),
	}

	for _, p := range providers {
		p.Register(app)
	}

	return app
}
