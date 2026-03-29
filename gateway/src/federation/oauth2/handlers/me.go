package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"openauth/gateway/transport"
)

type MeHandler struct {
	worker transport.Worker
}

func NewMeHandler(worker transport.Worker) *MeHandler {
	return &MeHandler{worker: worker}
}

func (h *MeHandler) GetMe(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	result, err := h.worker.Verify(token)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized", ErrorDescription: err.Error()})
	}

	return c.JSON(result)
}

func (h *MeHandler) PostLogout(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	if err := h.worker.Logout(token); err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized", ErrorDescription: err.Error()})
	}

	return c.JSON(map[string]bool{"ok": true})
}

func bearerToken(c fiber.Ctx) (string, bool) {
	auth := c.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return "", false
	}
	return token, true
}
