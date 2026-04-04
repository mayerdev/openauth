package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/oauth2"
)

type CredentialLinkOAuthHandler struct {
	worker      transport.Worker
	oauthStates *services.OAuthStateService
}

func NewCredentialLinkOAuthHandler(worker transport.Worker, oauthStates *services.OAuthStateService) *CredentialLinkOAuthHandler {
	return &CredentialLinkOAuthHandler{worker: worker, oauthStates: oauthStates}
}

func (h *CredentialLinkOAuthHandler) PostStart(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	provider := c.Params("provider")

	providerCfg := utils.FindOAuthProvider(provider)
	if providerCfg == nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "unknown provider"})
	}

	endpoint, ok := providerEndpoints[provider]
	if !ok {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "unsupported provider"})
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	codeVerifier := hex.EncodeToString(b)

	state, err := h.oauthStates.Store(c.Context(), services.OAuthState{
		AccessToken:  token,
		CodeVerifier: codeVerifier,
	}, 10*time.Minute)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	redirectURI := providerCfg.LinkRedirectURI
	if redirectURI == "" {
		redirectURI = providerCfg.RedirectURI
	}

	oauthConfig := &oauth2.Config{
		ClientID:     providerCfg.ClientID,
		ClientSecret: providerCfg.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     endpoint,
		Scopes:       providerScopes(provider),
	}

	authURL := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))

	return c.JSON(OAuthStartResponse{RedirectURL: authURL})
}

func (h *CredentialLinkOAuthHandler) GetCallback(c fiber.Ctx) error {
	provider := c.Params("provider")

	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "missing code or state"})
	}

	oauthState, err := h.oauthStates.Consume(c.Context(), state)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid or expired state"})
	}

	if oauthState.AccessToken == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "not a link flow"})
	}

	providerCfg := utils.FindOAuthProvider(provider)
	if providerCfg == nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "unknown provider"})
	}

	endpoint := providerEndpoints[provider]

	redirectURI := providerCfg.LinkRedirectURI
	if redirectURI == "" {
		redirectURI = providerCfg.RedirectURI
	}

	oauthConfig := &oauth2.Config{
		ClientID:     providerCfg.ClientID,
		ClientSecret: providerCfg.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     endpoint,
		Scopes:       providerScopes(provider),
	}

	oauthToken, err := oauthConfig.Exchange(context.Background(), code, oauth2.VerifierOption(oauthState.CodeVerifier))
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: "failed to exchange code"})
	}

	userInfo, err := fetchUserInfo(provider, oauthToken.AccessToken)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error", ErrorDescription: "failed to fetch user info"})
	}

	result, err := h.worker.LinkOAuth(oauthState.AccessToken, provider, userInfo.id(), userInfo.Email, userInfo.name(), "", "")
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	if !result.Ok {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	return c.JSON(map[string]bool{"ok": true})
}
