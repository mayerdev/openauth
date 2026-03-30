package oauth2

import (
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"openauth/gateway/federation"
	"openauth/gateway/federation/oauth2/handlers"
	"openauth/gateway/services"
	"openauth/gateway/transport"
)

var _ federation.Provider = (*Provider)(nil)

type Provider struct {
	authorizeHandler        *handlers.AuthorizeHandler
	loginHandler            *handlers.LoginHandler
	tfaHandler              *handlers.TFAHandler
	tokenHandler            *handlers.TokenHandler
	registerHandler         *handlers.RegisterHandler
	credentialVerifyHandler *handlers.CredentialVerifyHandler
	oauthMethodHandler      *handlers.OAuthMethodHandler
	web3MethodHandler       *handlers.Web3MethodHandler
}

func NewProvider(worker transport.Worker, sessions *services.AuthSessionService, codes *services.AuthCodeService, rdb *redis.Client) *Provider {
	oauthStates := services.NewOAuthStateService(rdb)
	web3Nonces := services.NewWeb3NonceService(rdb)

	return &Provider{
		authorizeHandler:        handlers.NewAuthorizeHandler(sessions),
		loginHandler:            handlers.NewLoginHandler(sessions, worker, codes),
		tfaHandler:              handlers.NewTFAHandler(sessions, worker, codes),
		tokenHandler:            handlers.NewTokenHandler(worker, codes),
		registerHandler:         handlers.NewRegisterHandler(sessions, worker, codes),
		credentialVerifyHandler: handlers.NewCredentialVerifyHandler(sessions, worker, codes),
		oauthMethodHandler:      handlers.NewOAuthMethodHandler(sessions, oauthStates, worker, codes),
		web3MethodHandler:       handlers.NewWeb3MethodHandler(sessions, web3Nonces, worker, codes),
	}
}

func (p *Provider) Name() string { return "oauth2" }

func (p *Provider) Register(app *fiber.App) {
	g := app.Group("/oauth2")
	g.Get("/authorize", p.authorizeHandler.GetAuthorize)
	g.Post("/authorize", p.loginHandler.PostAuthorize)
	g.Post("/tfa", p.tfaHandler.PostTFA)
	g.Post("/token", p.tokenHandler.PostToken)

	methods := g.Group("/methods")
	methods.Post("/email/login", p.loginHandler.PostAuthorize)
	methods.Post("/email/register", p.registerHandler.PostRegister)
	methods.Post("/email/verify", p.credentialVerifyHandler.PostVerify)
	methods.Post("/email/verify/resend", p.credentialVerifyHandler.PostResend)
	methods.Post("/oauth/:provider/start", p.oauthMethodHandler.PostStart)
	methods.Get("/oauth/:provider/callback", p.oauthMethodHandler.GetCallback)
	methods.Post("/web3/start", p.web3MethodHandler.PostStart)
	methods.Post("/web3/consume", p.web3MethodHandler.PostConsume)
}
