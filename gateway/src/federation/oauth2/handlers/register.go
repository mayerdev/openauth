package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type RegisterHandler struct {
	sessions AuthSessionRepo
	worker   transport.Worker
	codes    AuthCodeRepo
}

func NewRegisterHandler(sessions AuthSessionRepo, worker transport.Worker, codes AuthCodeRepo) *RegisterHandler {
	return &RegisterHandler{sessions: sessions, worker: worker, codes: codes}
}

func (h *RegisterHandler) PostRegister(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	sess, err := h.sessions.Get(c.Context(), req.AuthSessionID)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid auth_session_id"})
	}

	result, err := h.worker.Register(req.Email, req.Password)
	if err != nil {
		resp := ErrorResponse{Error: "registration_failed", ErrorDescription: err.Error()}
		var ve *transport.WorkerValidationError
		if errors.As(err, &ve) {
			resp.Errors = make([]FieldError, len(ve.Fields))
			for i, f := range ve.Fields {
				resp.Errors[i] = FieldError{Reason: f.Reason, Message: f.Message}
			}
		}
		return c.Status(400).JSON(resp)
	}

	return issueCodeAndRedirect(c, h.sessions, h.codes, sess, req.AuthSessionID, result.AccessToken, result.RefreshToken)
}
