package handlers

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type TFAHandler struct {
	sessions AuthSessionRepo
	worker   transport.Worker
	codes    AuthCodeRepo
}

func NewTFAHandler(sessions AuthSessionRepo, worker transport.Worker, codes AuthCodeRepo) *TFAHandler {
	return &TFAHandler{sessions: sessions, worker: worker, codes: codes}
}

func (h *TFAHandler) PostTFA(c fiber.Ctx) error {
	var req TFARequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	sess, err := h.sessions.Get(c.Context(), req.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	tokens, err := h.worker.TFAVerify(req.TFASessionID, req.Code)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "invalid_grant", ErrorDescription: err.Error()})
	}

	loginHandler := &LoginHandler{sessions: h.sessions, worker: h.worker, codes: h.codes}

	return loginHandler.issueCodeAndRedirect(c, sess, req.AuthSessionID, tokens.AccessToken, tokens.RefreshToken)
}
