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
	casbinutil "openauth/worker/utils/casbin"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sender"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type CredentialVerifyRequest struct {
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
	Scope     string `json:"scope"`
}

type CredentialVerifyResendRequest struct {
	SessionID string `json:"session_id"`
}

func CredentialVerify(msg *nats.Msg) {
	var req CredentialVerifyRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.SessionID == "" || req.Code == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	ctx := context.Background()
	userID, credType, credValue, payload, err := sessions.GetVerificationSession(ctx, req.SessionID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	ok, err := sessions.VerifyVerificationCode(ctx, req.SessionID, req.Code)
	if err != nil {
		if errors.Is(err, sessions.ErrMaxAttempts) {
			msg.Respond(types.EmitError("Max attempts exceeded", types.NoErrors))
			return
		}

		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if !ok {
		msg.Respond(types.EmitError("Invalid code", types.NoErrors))
		return
	}

	if password, ok := payload["password"]; ok {
		if err := utils.Database.Transaction(func(tx *gorm.DB) error {
			user := models.User{Password: password}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}

			cred, err := credentials.UpsertCredential(tx, user.ID, credType, credValue)
			if err != nil {
				return err
			}

			if err := tx.Model(cred).Update("verified", true).Error; err != nil {
				return err
			}

			userID = user.ID

			if role := utils.Config.Auth.DefaultRole; role != "" {
				_, _ = casbinutil.Enforcer.AddRoleForUser(user.ID.String(), role)
			}
			return nil
		}); err != nil {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
			return
		}
	} else {
		if err := utils.Database.Model(&models.UserCredential{}).
			Where("user_id = ? AND type = ?", userID, credType).
			Update("verified", true).Error; err != nil {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
			return
		}
	}

	_ = sessions.DeleteVerificationCode(ctx, req.SessionID)
	_ = sessions.DeleteVerificationSession(ctx, req.SessionID)

	sessionID, err := sessions.GenerateSessionID()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	accessToken, err := sessions.GenerateAccessToken(userID, sessionID, req.Scope)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(userID, sessionID, req.Scope)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if err := sessions.SaveSession(ctx, sessionID, userID, time.Duration(utils.Config.JWT.RefreshTokenTTL)*time.Second); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	msg.Respond(data)
}

func CredentialVerifyResend(msg *nats.Msg) {
	var req CredentialVerifyResendRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.SessionID == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	ctx := context.Background()

	userID, credType, credValue, _, err := sessions.GetVerificationSession(ctx, req.SessionID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	if err := sessions.CheckAndSetResendInterval(ctx, req.SessionID); err != nil {
		if errors.Is(err, sessions.ErrResendTooSoon) {
			msg.Respond(types.EmitError("Resend too soon", types.NoErrors))
			return
		}

		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	_ = sessions.DeleteVerificationCode(ctx, req.SessionID)

	codeTTL := time.Duration(utils.Config.Verification.CodeTTL) * time.Second
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	if err := sessions.StoreVerificationCode(ctx, req.SessionID, userID, code, credType, codeTTL); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	sendType := "sms"
	if credType == "email" {
		sendType = "email"
	}

	sender.SendCode(utils.Nats, sendType, credValue, code)

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
