package credentials

import (
	"context"
	"encoding/json"
	"errors"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type UnlinkDirectRequest struct {
	AccessToken  string `json:"access_token"`
	CredentialID string `json:"credential_id"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

func countVerifiedCredentials(db *gorm.DB, userID uuid.UUID) (int64, error) {
	var count int64
	err := db.Model(&models.UserCredential{}).
		Where("user_id = ? AND verified = true", userID).
		Count(&count).Error

	return count, err
}

func UnlinkDirect(msg *nats.Msg) {
	var req UnlinkDirectRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.CredentialID == "" {
		msg.Respond(types.EmitError("credential_id is required", types.NoErrors))
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

	credID, err := uuid.Parse(req.CredentialID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid credential_id", types.NoErrors))
		return
	}

	var cred models.UserCredential
	if err := utils.Database.Where("id = ? AND user_id = ?", credID, claims.UserID).First(&cred).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			msg.Respond(types.EmitError("Credential not found", types.NoErrors))
		} else {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
		}

		return
	}

	count, err := countVerifiedCredentials(utils.Database, claims.UserID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if count <= 1 {
		msg.Respond(types.EmitError("Cannot unlink the last credential", types.NoErrors))
		return
	}

	if err := utils.Database.Where("id = ? AND user_id = ?", credID, claims.UserID).Delete(&models.UserCredential{}).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
