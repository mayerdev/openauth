package handlers

import (
	"openauth/gateway/transport"

	"github.com/gofiber/fiber/v3"
)

type HistoryHandler struct {
	worker transport.Worker
}

func NewHistoryHandler(worker transport.Worker) *HistoryHandler {
	return &HistoryHandler{worker: worker}
}

type historyQuery struct {
	Page     int `query:"page"`
	PageSize int `query:"page_size"`
}

func (h *HistoryHandler) GetHistory(c fiber.Ctx) error {
	token, ok := bearerToken(c)
	if !ok {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized"})
	}

	var q historyQuery
	_ = c.Bind().Query(&q)

	result, err := h.worker.GetAuthHistory(token, q.Page, q.PageSize)
	if err != nil {
		return c.Status(401).JSON(ErrorResponse{Error: "unauthorized", ErrorDescription: err.Error()})
	}

	return c.JSON(result)
}
