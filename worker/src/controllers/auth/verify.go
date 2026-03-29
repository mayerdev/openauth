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

type VerifyRequest struct {
	AccessToken string `json:"access_token"`
}

type CredentialResult struct {
	ID       uuid.UUID `json:"id"`
	Type     string    `json:"type"`
	Value    string    `json:"value"`
	Verified bool      `json:"verified"`
}

type UserResult struct {
	ID          uuid.UUID          `json:"id"`
	Status      string             `json:"status"`
	TfaMethod   string             `json:"tfa_method"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Credentials []CredentialResult `json:"credentials"`
}

func Verify(msg *nats.Msg) {
	var req VerifyRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	ctx := context.Background()

	exists, err := sessions.SessionExists(ctx, claims.SessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}
	if !exists {
		msg.Respond(types.EmitError("Session not found", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("User not found", types.NoErrors))
		return
	}

	var creds []models.UserCredential
	utils.Database.Where("user_id = ?", user.ID).Find(&creds)

	credResults := make([]CredentialResult, len(creds))
	for i, c := range creds {
		credResults[i] = CredentialResult{
			ID:       c.ID,
			Type:     c.Type,
			Value:    c.Value,
			Verified: c.Verified,
		}
	}

	data, _ := json.Marshal(UserResult{
		ID:          user.ID,
		Status:      user.Status,
		TfaMethod:   user.TfaMethod,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Credentials: credResults,
	})
	msg.Respond(data)
}
