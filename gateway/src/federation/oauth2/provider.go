package oauth2

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/federation"
	"openauth/gateway/federation/oauth2/handlers"
	"openauth/gateway/services"
	"openauth/gateway/transport"
)

var _ federation.Provider = (*Provider)(nil)

type Provider struct {
	authorizeHandler *handlers.AuthorizeHandler
	loginHandler     *handlers.LoginHandler
	tfaHandler       *handlers.TFAHandler
	tokenHandler     *handlers.TokenHandler
	registerHandler  *handlers.RegisterHandler
}

func NewProvider(worker transport.Worker, sessions *services.AuthSessionService, codes *services.AuthCodeService) *Provider {
	return &Provider{
		authorizeHandler: handlers.NewAuthorizeHandler(sessions),
		loginHandler:     handlers.NewLoginHandler(sessions, worker, codes),
		tfaHandler:       handlers.NewTFAHandler(sessions, worker, codes),
		tokenHandler:     handlers.NewTokenHandler(worker, codes),
		registerHandler:  handlers.NewRegisterHandler(sessions, worker, codes),
	}
}

func (p *Provider) Name() string { return "oauth2" }

func (p *Provider) Register(app *fiber.App) {
	g := app.Group("/oauth2")
	g.Post("/register", p.registerHandler.PostRegister)
	g.Get("/authorize", p.authorizeHandler.GetAuthorize)
	g.Post("/authorize", p.loginHandler.PostAuthorize)
	g.Post("/tfa", p.tfaHandler.PostTFA)
	g.Post("/token", p.tokenHandler.PostToken)
}
