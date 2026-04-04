package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sender"
	"openauth/worker/utils/sessions"
	tfautil "openauth/worker/utils/tfa"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

type tfaRequiredResult struct {
	TfaRequired  bool   `json:"tfa_required"`
	TfaSessionID string `json:"tfa_session_id"`
	TfaMethod    string `json:"tfa_method"`
	ExpiresIn    int    `json:"expires_in"`
}

func startCredentialTFA(user *models.User) (*tfaRequiredResult, error) {
	ctx := context.Background()

	tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, "", 5*time.Minute, "")
	if err != nil {
		return nil, err
	}

	if user.TfaMethod == "email" || user.TfaMethod == "phone" {
		var allCreds []models.UserCredential
		utils.Database.Where("user_id = ?", user.ID).Find(&allCreds)

		code := fmt.Sprintf("%06d", rand.Intn(1000000))
		_ = sessions.StoreTfaCode(ctx, tfaSessionID, user.ID, code, user.TfaMethod, 5*time.Minute)

		sendType := "sms"
		credType := credentials.CredentialTypePhone
		if user.TfaMethod == "email" {
			sendType = "email"
			credType = credentials.CredentialTypeEmail
		}

		for _, c := range allCreds {
			if c.Type == credType {
				sender.SendCode(utils.Nats, sendType, c.Value, code)
				break
			}
		}
	}

	return &tfaRequiredResult{
		TfaRequired:  true,
		TfaSessionID: tfaSessionID,
		TfaMethod:    user.TfaMethod,
		ExpiresIn:    300,
	}, nil
}

func verifyCredentialTFA(sessionID, code string, user *models.User) error {
	if code == "" {
		return fmt.Errorf("code is required")
	}

	ctx := context.Background()

	userID, method, _, err := sessions.GetTfaSession(ctx, sessionID)
	if err != nil || userID != user.ID {
		return fmt.Errorf("Invalid session")
	}

	var verified bool

	switch method {
	case "totp":
		if user.TfaSecret == nil {
			return fmt.Errorf("2FA not configured")
		}

		if tfautil.VerifyCode(*user.TfaSecret, code) {
			verified = true
		} else {
			var backupCodes []string
			if user.TfaBackupCodes != nil {
				_ = json.Unmarshal(user.TfaBackupCodes, &backupCodes)
			}

			for i, c := range backupCodes {
				if c != "" && c == code {
					verified = true
					backupCodes[i] = ""
					updated, _ := json.Marshal(backupCodes)
					utils.Database.Model(user).Update("tfa_backup_codes", updated)
					break
				}
			}
		}

	case "email", "phone":
		ok, err := sessions.VerifyTfaCode(ctx, sessionID, userID.String(), code)
		if err != nil {
			if errors.Is(err, sessions.ErrMaxAttempts) {
				return fmt.Errorf("Max attempts exceeded")
			}

			return fmt.Errorf("Internal error")
		}

		if ok {
			verified = true
			_ = sessions.DeleteTfaCode(ctx, sessionID)
		}
	}

	if !verified {
		return fmt.Errorf("Invalid code")
	}

	_ = sessions.DeleteTfaSession(ctx, sessionID)

	return nil
}

type tfaResendRequest struct {
	AccessToken  string `json:"access_token"`
	TfaSessionID string `json:"tfa_session_id"`
}

func TfaResend(msg *nats.Msg) {
	var req tfaResendRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.TfaSessionID == "" {
		msg.Respond(types.EmitError("tfa_session_id is required", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	ctx := context.Background()

	userID, _, _, err := sessions.GetTfaSession(ctx, req.TfaSessionID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	if userID != claims.UserID {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	if err := sessions.CheckTfaResend(ctx, req.TfaSessionID); err != nil {
		if errors.Is(err, sessions.ErrResendTooSoon) {
			msg.Respond(types.EmitError("Resend too soon", types.NoErrors))
			return
		}

		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if user.TfaMethod != "email" && user.TfaMethod != "phone" {
		msg.Respond(types.EmitError("Resend not available for this TFA method", types.NoErrors))
		return
	}

	_ = sessions.DeleteTfaCode(ctx, req.TfaSessionID)

	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	if err := sessions.StoreTfaCode(ctx, req.TfaSessionID, claims.UserID, code, user.TfaMethod, 5*time.Minute); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	sendType := "sms"
	credType := credentials.CredentialTypePhone
	if user.TfaMethod == "email" {
		sendType = "email"
		credType = credentials.CredentialTypeEmail
	}

	var allCreds []models.UserCredential
	utils.Database.Where("user_id = ? AND type = ?", claims.UserID, credType).Find(&allCreds)
	for _, c := range allCreds {
		sender.SendCode(utils.Nats, sendType, c.Value, code)
		break
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
