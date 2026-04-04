package credentials

import (
	"context"
	"encoding/json"
	"errors"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type LinkOAuthRequest struct {
	AccessToken  string `json:"access_token"`
	Provider     string `json:"provider"`
	ProviderID   string `json:"provider_id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

func LinkOAuth(msg *nats.Msg) {
	var req LinkOAuthRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Provider == "" || req.ProviderID == "" {
		msg.Respond(types.EmitError("provider and provider_id are required", types.NoErrors))
		return
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

	var currentUser models.User
	if err := utils.Database.First(&currentUser, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if currentUser.TfaMethod != "none" {
		if req.TfaSessionID == "" {
			result, err := startCredentialTFA(&currentUser)
			if err != nil {
				msg.Respond(types.EmitError("Internal error", types.NoErrors))
				return
			}

			data, _ := json.Marshal(result)
			msg.Respond(data)
			return
		}

		if err := verifyCredentialTFA(req.TfaSessionID, req.Code, &currentUser); err != nil {
			msg.Respond(types.EmitError(err.Error(), types.NoErrors))
			return
		}
	}

	credType := credentials.CredentialTypeOAuth(req.Provider)

	user, _, err := credentials.FindUserByCredential(utils.Database, credType, req.ProviderID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if user != nil {
		if user.ID == claims.UserID {
			msg.Respond(types.EmitError("Credential already linked", types.NoErrors))
		} else {
			msg.Respond(types.EmitError("Already linked to another account", types.NoErrors))
		}

		return
	}

	cred, err := credentials.UpsertCredential(utils.Database, claims.UserID, credType, req.ProviderID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if err := utils.Database.Model(cred).Update("verified", true).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
