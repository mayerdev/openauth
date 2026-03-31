package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"openauth/gateway/services"
	"openauth/gateway/transport"
	"openauth/gateway/utils"
)

type AuthSessionRepo interface {
	Create(ctx context.Context, sess services.AuthSession, ttl time.Duration) (string, error)
	Get(ctx context.Context, id string) (*services.AuthSession, error)
	Delete(ctx context.Context, id string) error
}

type AuthCodeRepo interface {
	Create(ctx context.Context, entry services.AuthCodeEntry, ttl time.Duration) (string, error)
	Consume(ctx context.Context, code string) (*services.AuthCodeEntry, error)
}

type AuthorizeHandler struct {
	sessions AuthSessionRepo
}

func NewAuthorizeHandler(sessions AuthSessionRepo) *AuthorizeHandler {
	return &AuthorizeHandler{sessions: sessions}
}

func (h *AuthorizeHandler) GetAuthorize(c fiber.Ctx) error {
	var q AuthorizeQueryParams
	if err := c.Bind().Query(&q); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	if q.ResponseType != "code" {
		return c.Status(400).JSON(ErrorResponse{Error: "unsupported_response_type"})
	}

	client := utils.FindClient(q.ClientID)
	if client == nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_client", ErrorDescription: "unknown client_id"})
	}

	if !redirectURIAllowed(client.RedirectURIs, q.RedirectURI) {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "redirect_uri not allowed"})
	}

	scope := q.Scope
	if scope == "" {
		scope = "openid"
	}

	sessID, err := h.sessions.Create(c.Context(), services.AuthSession{
		ClientID:    q.ClientID,
		RedirectURI: q.RedirectURI,
		State:       q.State,
		Scope:       scope,
	}, 10*time.Minute)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	return c.JSON(AuthorizeInitResponse{
		AuthSessionID: sessID,
		ClientName:    client.Name,
		Scope:         scope,
	})
}

type LoginHandler struct {
	sessions AuthSessionRepo
	worker   transport.Worker
	codes    AuthCodeRepo
}

func NewLoginHandler(sessions AuthSessionRepo, worker transport.Worker, codes AuthCodeRepo) *LoginHandler {
	return &LoginHandler{sessions: sessions, worker: worker, codes: codes}
}

func (h *LoginHandler) PostAuthorize(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	sess, err := h.sessions.Get(c.Context(), req.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	// TFA step: tfa_session_id + code present
	if req.TFASessionID != "" && req.Code != "" {
		tokens, err := h.worker.TFAVerify(req.TFASessionID, req.Code, sess.Scope)
		if err != nil {
			return c.Status(401).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: err.Error()})
		}
		return h.issueCodeAndRedirect(c, sess, req.AuthSessionID, tokens.AccessToken, tokens.RefreshToken)
	}

	// Login step
	method := req.Method
	if method == "" {
		method = "email"
	}
	identifier := req.Email
	if method == "phone" {
		identifier = req.Phone
	}

	result, err := h.worker.Login(method, identifier, req.Password, sess.Scope)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_credentials", ErrorDescription: err.Error()})
	}

	if result.TFARequired {
		return c.JSON(TFARequiredResponse{
			TFARequired:  true,
			TFASessionID: result.TFASessionID,
			TFAMethod:    result.TFAMethod,
			ExpiresIn:    result.ExpiresIn,
		})
	}

	return h.issueCodeAndRedirect(c, sess, req.AuthSessionID, result.AccessToken, result.RefreshToken)
}

func (h *LoginHandler) issueCodeAndRedirect(c fiber.Ctx, sess *services.AuthSession, sessID, accessToken, refreshToken string) error {
	return issueCodeAndRedirect(c, h.sessions, h.codes, sess, sessID, accessToken, refreshToken)
}

func issueCodeAndRedirect(c fiber.Ctx, sessions AuthSessionRepo, codes AuthCodeRepo, sess *services.AuthSession, sessID, accessToken, refreshToken string) error {
	code, err := codes.Create(c.Context(), services.AuthCodeEntry{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scope:        sess.Scope,
		ClientID:     sess.ClientID,
		RedirectURI:  sess.RedirectURI,
	}, 10*time.Minute)
	if err != nil {
		return c.Status(500).JSON(ErrorResponse{Error: "server_error"})
	}

	sessions.Delete(c.Context(), sessID)

	return c.JSON(LoginSuccessResponse{
		RedirectURL: buildRedirectURL(sess.RedirectURI, code, sess.State),
	})
}

func redirectURIAllowed(allowed []string, uri string) bool {
	for _, u := range allowed {
		if u == uri {
			return true
		}
	}

	return false
}

func buildRedirectURL(redirectURI, code, state string) string {
	u := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		u += "&state=" + state
	}

	return u
}
