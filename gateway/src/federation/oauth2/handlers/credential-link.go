package handlers

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type CredentialLinkHandler struct {
	worker transport.Worker
}

func NewCredentialLinkHandler(worker transport.Worker) *CredentialLinkHandler {
	return &CredentialLinkHandler{worker: worker}
}

type linkStartRequest struct {
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

type linkConfirmRequest struct {
	VerificationSessionID string `json:"verification_session_id"`
	Code                  string `json:"code"`
}

func (h *CredentialLinkHandler) PostEmailLinkStart(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req linkStartRequest
	if err := c.Bind().Body(&req); err != nil || req.Email == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "email is required"})
	}

	result, err := h.worker.LinkEmailStart(token, req.Email, req.TfaSessionID, req.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	if result.TFARequired {
		return c.JSON(TFARequiredResponse{
			TFARequired:  true,
			TFASessionID: result.TFASessionID,
			TFAMethod:    result.TFAMethod,
			ExpiresIn:    result.ExpiresIn,
		})
	}

	return c.JSON(result)
}

func (h *CredentialLinkHandler) PostEmailLinkConfirm(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req linkConfirmRequest
	if err := c.Bind().Body(&req); err != nil || req.VerificationSessionID == "" || req.Code == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "verification_session_id and code are required"})
	}

	if err := h.worker.LinkEmailConfirm(token, req.VerificationSessionID, req.Code); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}

func (h *CredentialLinkHandler) PostPhoneLinkStart(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req linkStartRequest
	if err := c.Bind().Body(&req); err != nil || req.Phone == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "phone is required"})
	}

	result, err := h.worker.LinkPhoneStart(token, req.Phone, req.TfaSessionID, req.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	if result.TFARequired {
		return c.JSON(TFARequiredResponse{
			TFARequired:  true,
			TFASessionID: result.TFASessionID,
			TFAMethod:    result.TFAMethod,
			ExpiresIn:    result.ExpiresIn,
		})
	}

	return c.JSON(result)
}

func (h *CredentialLinkHandler) PostPhoneLinkConfirm(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var req linkConfirmRequest
	if err := c.Bind().Body(&req); err != nil || req.VerificationSessionID == "" || req.Code == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "verification_session_id and code are required"})
	}

	if err := h.worker.LinkPhoneConfirm(token, req.VerificationSessionID, req.Code); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}
