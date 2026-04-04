package auth

import (
	"context"
	"encoding/json"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

func saveAuthHistory(userID uuid.UUID, sessionID, method, ipAddress, userAgent string) {
	utils.Database.Create(&models.AuthHistory{
		UserID:    userID,
		SessionID: sessionID,
		Method:    method,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
}

type historyEntry struct {
	ID        uuid.UUID `json:"id"`
	SessionID string    `json:"session_id"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
}

type GetHistoryRequest struct {
	AccessToken string `json:"access_token"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
}

func GetHistory(msg *nats.Msg) {
	var req GetHistoryRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Page < 1 {
		req.Page = 1
	}

	if req.PageSize < 1 {
		req.PageSize = 20
	}

	if req.PageSize > 100 {
		req.PageSize = 100
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	ctx := context.Background()
	exists, err := sessions.SessionExists(ctx, claims.SessionID)
	if err != nil || !exists {
		msg.Respond(types.EmitError("Session not found", types.NoErrors))
		return
	}

	var total int64
	utils.Database.Model(&models.AuthHistory{}).
		Where("user_id = ?", claims.UserID).
		Count(&total)

	var records []models.AuthHistory
	utils.Database.
		Where("user_id = ?", claims.UserID).
		Order("created_at DESC").
		Limit(req.PageSize).
		Offset((req.Page - 1) * req.PageSize).
		Find(&records)

	entries := make([]historyEntry, len(records))
	for i, r := range records {
		entries[i] = historyEntry{
			ID:        r.ID,
			SessionID: r.SessionID,
			Method:    r.Method,
			UserAgent: r.UserAgent,
			IPAddress: r.IPAddress,
			CreatedAt: r.CreatedAt,
		}
	}

	data, _ := json.Marshal(map[string]any{
		"history":   entries,
		"total":     total,
		"page":      req.Page,
		"page_size": req.PageSize,
	})
	msg.Respond(data)
}
