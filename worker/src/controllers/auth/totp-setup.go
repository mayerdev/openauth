package auth

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

const (
	totpIssuer      = "openauth"
	totpSetupPrefix = "totp_setup"
	totpSetupTTL    = 10 * time.Minute
)

type TotpStartRequest struct {
	AccessToken  string `json:"access_token"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

type TotpConfirmRequest struct {
	AccessToken string `json:"access_token"`
	Code        string `json:"code"`
}

type TotpUnlinkRequest struct {
	AccessToken  string `json:"access_token"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

func TotpStart(msg *nats.Msg) {
	var req TotpStartRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.AccessToken == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Unauthorized", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if user.TfaMethod != "none" {
		if req.TfaSessionID == "" {
			result, err := startTfaFlow(&user)
			if err != nil {
				msg.Respond(types.EmitError("Internal error", types.NoErrors))
				return
			}

			data, _ := json.Marshal(result)
			msg.Respond(data)
			return
		}

		if err := verifyTfaFlow(req.TfaSessionID, req.Code, &user); err != nil {
			msg.Respond(types.EmitError(err.Error(), types.NoErrors))
			return
		}
	}

	secret, err := tfautil.GenerateSecret()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("%s:%s", totpSetupPrefix, claims.UserID.String())
	if err := utils.Redis.Set(ctx, key, secret, totpSetupTTL).Err(); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	var emailCred string
	var allCreds []models.UserCredential
	utils.Database.Where("user_id = ? AND type = ?", claims.UserID, credentials.CredentialTypeEmail).First(&allCreds)
	for _, c := range allCreds {
		emailCred = c.Value
		break
	}

	uri := tfautil.GetProvisioningURI(secret, emailCred, totpIssuer)

	data, _ := json.Marshal(map[string]string{
		"provisioning_uri": uri,
		"secret":           secret,
	})
	msg.Respond(data)
}

func TotpConfirm(msg *nats.Msg) {
	var req TotpConfirmRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.AccessToken == "" || req.Code == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Unauthorized", types.NoErrors))
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("%s:%s", totpSetupPrefix, claims.UserID.String())

	secret, err := utils.Redis.Get(ctx, key).Result()
	if err != nil {
		msg.Respond(types.EmitError("Setup session expired", types.NoErrors))
		return
	}

	if !tfautil.VerifyCode(secret, req.Code) {
		msg.Respond(types.EmitError("Invalid code", types.NoErrors))
		return
	}

	backupCodes := tfautil.GenerateBackupCodes(8)
	backupJSON, _ := json.Marshal(backupCodes)

	if err := utils.Database.Exec(
		"UPDATE users SET tfa_secret = ?, tfa_backup_codes = ? WHERE id = ?",
		secret, backupJSON, claims.UserID,
	).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	utils.Redis.Del(ctx, key)

	data, _ := json.Marshal(map[string][]string{"backup_codes": backupCodes})
	msg.Respond(data)
}

func TotpUnlink(msg *nats.Msg) {
	var req TotpUnlinkRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.AccessToken == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Unauthorized", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if user.TfaMethod != "none" {
		if req.TfaSessionID == "" {
			result, err := startTfaFlow(&user)
			if err != nil {
				msg.Respond(types.EmitError("Internal error", types.NoErrors))
				return
			}

			data, _ := json.Marshal(result)
			msg.Respond(data)
			return
		}

		if err := verifyTfaFlow(req.TfaSessionID, req.Code, &user); err != nil {
			msg.Respond(types.EmitError(err.Error(), types.NoErrors))
			return
		}
	}

	if err := utils.Database.Exec(
		"UPDATE users SET tfa_secret = NULL, tfa_backup_codes = NULL, tfa_method = CASE WHEN tfa_method = 'totp' THEN 'none' ELSE tfa_method END WHERE id = ?",
		claims.UserID,
	).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}

func startTfaFlow(user *models.User) (*TfaRequiredResult, error) {
	ctx := context.Background()
	tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, 5*time.Minute, "")
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

	return &TfaRequiredResult{
		TfaRequired:  true,
		TfaSessionID: tfaSessionID,
		TfaMethod:    user.TfaMethod,
		ExpiresIn:    300,
	}, nil
}

func verifyTfaFlow(sessionID, code string, user *models.User) error {
	if code == "" {
		return fmt.Errorf("code is required")
	}

	ctx := context.Background()
	userID, method, err := sessions.GetTfaSession(ctx, sessionID)
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
