package handlers

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type CredentialUnlinkHandler struct {
	worker transport.Worker
}

func NewCredentialUnlinkHandler(worker transport.Worker) *CredentialUnlinkHandler {
	return &CredentialUnlinkHandler{worker: worker}
}

type unlinkRequest struct {
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

func (h *CredentialUnlinkHandler) DeleteCredential(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	credentialID := c.Params("id")
	if credentialID == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "id is required"})
	}

	var req unlinkRequest
	_ = c.Bind().Body(&req)

	result, err := h.worker.UnlinkDirect(token, credentialID, req.TfaSessionID, req.Code)
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

	return c.JSON(map[string]bool{"ok": true})
}
