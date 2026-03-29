package handlers

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
	"openauth/gateway/utils"
)

type TokenHandler struct {
	worker transport.Worker
	codes  AuthCodeRepo
}

func NewTokenHandler(worker transport.Worker, codes AuthCodeRepo) *TokenHandler {
	return &TokenHandler{worker: worker, codes: codes}
}

func (h *TokenHandler) PostToken(c fiber.Ctx) error {
	var req TokenRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	client := utils.FindClient(req.ClientID)
	if client == nil || client.Secret != req.ClientSecret {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_client"})
	}

	switch req.GrantType {
	case "authorization_code":
		return h.handleAuthorizationCode(c, req, client)
	case "refresh_token":
		return h.handleRefreshToken(c, req)
	default:
		return c.Status(400).JSON(ErrorResponse{Error: "unsupported_grant_type"})
	}
}

func (h *TokenHandler) handleAuthorizationCode(c fiber.Ctx, req TokenRequest, client *utils.Client) error {
	if !redirectURIAllowed(client.RedirectURIs, req.RedirectURI) {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "redirect_uri mismatch"})
	}

	entry, err := h.codes.Consume(c.Context(), req.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: "code not found or expired"})
	}

	if entry.ClientID != req.ClientID || entry.RedirectURI != req.RedirectURI {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: "client or redirect_uri mismatch"})
	}

	return c.JSON(TokenResponse{
		AccessToken:  entry.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    utils.Config.JWT.AccessTokenTTL,
		RefreshToken: entry.RefreshToken,
		Scope:        entry.Scope,
	})
}

func (h *TokenHandler) handleRefreshToken(c fiber.Ctx, req TokenRequest) error {
	tokens, err := h.worker.RefreshToken(req.RefreshToken)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: err.Error()})
	}
	return c.JSON(TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    utils.Config.JWT.AccessTokenTTL,
		RefreshToken: tokens.RefreshToken,
	})
}
