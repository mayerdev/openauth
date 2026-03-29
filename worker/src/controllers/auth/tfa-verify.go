package auth

import (
	"context"
	"encoding/json"
	"errors"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/sessions"
	tfautil "openauth/worker/utils/tfa"
	"openauth/worker/utils/types"

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
)

type TfaVerifyRequest struct {
	SessionID string `json:"session_id" validate:"required"`
	Code      string `json:"code" validate:"required"`
}

func TfaVerify(msg *nats.Msg) {
	var req TfaVerifyRequest

	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if err := utils.Validator.Struct(&req); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			fieldErrors := make([]types.Error, len(ve))
			for i, fe := range ve {
				fieldErrors[i] = types.Error{Reason: fe.Field(), Message: fe.Tag()}
			}

			msg.Respond(types.EmitError("Validation error", fieldErrors))
			return
		}

		msg.Respond(types.EmitError("Validation error", types.NoErrors))
		return
	}

	ctx := context.Background()

	userID, method, err := sessions.GetTfaSession(ctx, req.SessionID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", userID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	var verified bool

	switch method {
	case "totp":
		if user.TfaSecret == nil {
			msg.Respond(types.EmitError("2FA not configured", types.NoErrors))
			return
		}

		if tfautil.VerifyCode(*user.TfaSecret, req.Code) {
			verified = true
		} else {
			var backupCodes []string
			if user.TfaBackupCodes != nil {
				_ = json.Unmarshal(user.TfaBackupCodes, &backupCodes)
			}

			for i, c := range backupCodes {
				if c != "" && c == req.Code {
					verified = true
					backupCodes[i] = ""
					updated, _ := json.Marshal(backupCodes)
					utils.Database.Model(&user).Update("tfa_backup_codes", updated)
					break
				}
			}
		}
	}

	if !verified {
		msg.Respond(types.EmitError("Invalid code", types.NoErrors))
		return
	}

	_ = sessions.DeleteTfaSession(ctx, req.SessionID)

	sessionID, err := sessions.GenerateSessionID()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	accessToken, err := sessions.GenerateAccessToken(userID, sessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(userID, sessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	msg.Respond(data)
}
