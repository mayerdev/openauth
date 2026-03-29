package router

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"openauth/gateway/federation"
	oauth2provider "openauth/gateway/federation/oauth2"
	"openauth/gateway/federation/oauth2/handlers"
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
		oauth2provider.NewProvider(worker, sessions, codes, utils.Redis),
	}

	for _, p := range providers {
		p.Register(app)
	}

	me := handlers.NewMeHandler(worker)
	totp := handlers.NewTotpHandler(worker)

	api := app.Group("/api")
	api.Get("/me", me.GetMe)
	api.Post("/logout", me.PostLogout)
	api.Post("/totp/start", totp.PostTotpStart)
	api.Post("/totp/confirm", totp.PostTotpConfirm)
	api.Post("/totp/unlink", totp.PostTotpUnlink)
	api.Get("/tfa/method", totp.GetTfaMethod)
	api.Put("/tfa/method", totp.PutTfaMethod)

	return app
}
