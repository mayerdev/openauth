package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
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
	AccessToken string `json:"access_token"`
}

type TotpConfirmRequest struct {
	AccessToken string `json:"access_token"`
	Code        string `json:"code"`
}

type TotpUnlinkRequest struct {
	AccessToken string `json:"access_token"`
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
