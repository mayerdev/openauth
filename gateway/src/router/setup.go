package router

import (
	"time"

	"openauth/gateway/federation"
	oauth2provider "openauth/gateway/federation/oauth2"
	"openauth/gateway/federation/oauth2/handlers"
	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"

	"github.com/gofiber/fiber/v3"
)

func Setup() *fiber.App {
	app := fiber.New(fiber.Config{AppName: "openauth-gateway"})

	worker := transport.NewWorkerClient(utils.Nats, 10*time.Second)
	sessions := services.NewAuthSessionService(utils.Redis)
	codes := services.NewAuthCodeService(utils.Redis)
	oauthStates := services.NewOAuthStateService(utils.Redis)
	web3Nonces := services.NewWeb3NonceService(utils.Redis)

	providers := []federation.Provider{
		oauth2provider.NewProvider(worker, sessions, codes, oauthStates, web3Nonces),
	}

	for _, p := range providers {
		p.Register(app)
	}

	me := handlers.NewMeHandler(worker)
	totp := handlers.NewTotpHandler(worker)
	history := handlers.NewHistoryHandler(worker)
	credLink := handlers.NewCredentialLinkHandler(worker)
	credLinkOAuth := handlers.NewCredentialLinkOAuthHandler(worker, oauthStates)
	credLinkWeb3 := handlers.NewCredentialLinkWeb3Handler(worker, web3Nonces)
	credUnlink := handlers.NewCredentialUnlinkHandler(worker)

	api := app.Group("/api")
	api.Post("/logout", me.PostLogout)
	api.Post("/totp/start", totp.PostTotpStart)
	api.Post("/totp/confirm", totp.PostTotpConfirm)
	api.Post("/totp/unlink", totp.PostTotpUnlink)
	api.Post("/tfa/resend", totp.PostTfaResend)
	api.Get("/tfa/method", totp.GetTfaMethod)
	api.Put("/tfa/method", totp.PutTfaMethod)
	api.Get("/history", history.GetHistory)

	creds := api.Group("/credentials")
	creds.Post("/email/start", credLink.PostEmailLinkStart)
	creds.Post("/email/confirm", credLink.PostEmailLinkConfirm)
	creds.Post("/phone/start", credLink.PostPhoneLinkStart)
	creds.Post("/phone/confirm", credLink.PostPhoneLinkConfirm)
	creds.Post("/oauth/:provider/start", credLinkOAuth.PostStart)
	creds.Get("/oauth/:provider/callback", credLinkOAuth.GetCallback)
	creds.Post("/web3/start", credLinkWeb3.PostStart)
	creds.Post("/web3/consume", credLinkWeb3.PostConsume)
	creds.Delete("/:id", credUnlink.DeleteCredential)

	return app
}
