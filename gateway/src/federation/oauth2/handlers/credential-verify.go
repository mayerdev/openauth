package handlers

import (
	"openauth/gateway/transport"

	"github.com/gofiber/fiber/v3"
)

type CredentialVerifyHandler struct {
	sessions AuthSessionRepo
	worker   transport.Worker
	codes    AuthCodeRepo
}

func NewCredentialVerifyHandler(sessions AuthSessionRepo, worker transport.Worker, codes AuthCodeRepo) *CredentialVerifyHandler {
	return &CredentialVerifyHandler{sessions: sessions, worker: worker, codes: codes}
}

func (h *CredentialVerifyHandler) PostVerify(c fiber.Ctx) error {
	var req CredentialVerifyRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	sess, err := h.sessions.Get(c.Context(), req.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	result, err := h.worker.CredentialVerify(req.VerificationSessionID, req.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "verification_failed", ErrorDescription: err.Error()})
	}

	return issueCodeAndRedirect(c, h.sessions, h.codes, sess, req.AuthSessionID, result.AccessToken, result.RefreshToken)
}

func (h *CredentialVerifyHandler) PostResend(c fiber.Ctx) error {
	var req CredentialVerifyResendRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	if err := h.worker.CredentialVerifyResend(req.VerificationSessionID); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "resend_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}
