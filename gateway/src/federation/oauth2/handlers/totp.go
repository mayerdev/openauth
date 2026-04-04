package handlers

import (
	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type TotpHandler struct {
	worker transport.Worker
}

func NewTotpHandler(worker transport.Worker) *TotpHandler {
	return &TotpHandler{worker: worker}
}

func (h *TotpHandler) PostTotpStart(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var body struct {
		TfaSessionID string `json:"tfa_session_id"`
		Code         string `json:"code"`
	}

	_ = c.Bind().Body(&body)

	result, err := h.worker.TotpStart(token, body.TfaSessionID, body.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "request_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(result)
}

func (h *TotpHandler) PostTotpConfirm(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := c.Bind().Body(&body); err != nil || body.Code == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	result, err := h.worker.TotpConfirm(token, body.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "request_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(result)
}

func (h *TotpHandler) PostTotpUnlink(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var body struct {
		TfaSessionID string `json:"tfa_session_id"`
		Code         string `json:"code"`
	}

	_ = c.Bind().Body(&body)

	result, err := h.worker.TotpUnlink(token, body.TfaSessionID, body.Code)
	if err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "request_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(result)
}

func (h *TotpHandler) GetTfaMethod(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	method, err := h.worker.TfaMethodGet(token)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]string{"method": method})
}

func (h *TotpHandler) PostTfaResend(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var body struct {
		TfaSessionID string `json:"tfa_session_id"`
	}

	if err := c.Bind().Body(&body); err != nil || body.TfaSessionID == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request", ErrorDescription: "tfa_session_id is required"})
	}

	if err := h.worker.TfaResend(token, body.TfaSessionID); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "request_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}

func (h *TotpHandler) PutTfaMethod(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var body struct {
		Method string `json:"method"`
	}
	if err := c.Bind().Body(&body); err != nil || body.Method == "" {
		return c.Status(400).JSON(ErrorResponse{Error: "invalid_request"})
	}

	if err := h.worker.TfaMethodSet(token, body.Method); err != nil {
		return c.Status(400).JSON(ErrorResponse{Error: "request_failed", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}
