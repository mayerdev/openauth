package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sender"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type LinkEmailStartRequest struct {
	AccessToken  string `json:"access_token"`
	Email        string `json:"email"`
	TfaSessionID string `json:"tfa_session_id"`
	Code         string `json:"code"`
}

type LinkEmailConfirmRequest struct {
	AccessToken           string `json:"access_token"`
	VerificationSessionID string `json:"verification_session_id"`
	Code                  string `json:"code"`
}

func LinkEmailStart(msg *nats.Msg) {
	var req LinkEmailStartRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Email == "" {
		msg.Respond(types.EmitError("Email is required", types.NoErrors))
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

	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, _, err := credentials.FindUserByCredential(utils.Database, credentials.CredentialTypeEmail, email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if user != nil {
		if user.ID == claims.UserID {
			msg.Respond(types.EmitError("Email already linked", types.NoErrors))
		} else {
			msg.Respond(types.EmitError("Email already in use", types.NoErrors))
		}

		return
	}

	codeTTL := time.Duration(utils.Config.Verification.CodeTTL) * time.Second

	sessionID, err := sessions.CreateVerificationSession(ctx, claims.UserID, credentials.CredentialTypeEmail, email, codeTTL, nil)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	if err := sessions.StoreVerificationCode(ctx, sessionID, claims.UserID, code, credentials.CredentialTypeEmail, codeTTL); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	sender.SendCode(utils.Nats, "email", email, code)

	data, _ := json.Marshal(map[string]any{
		"verification_session_id": sessionID,
		"verification_method":     "email",
		"expires_in":              int(codeTTL.Seconds()),
	})
	msg.Respond(data)
}

func LinkEmailConfirm(msg *nats.Msg) {
	var req LinkEmailConfirmRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.VerificationSessionID == "" || req.Code == "" {
		msg.Respond(types.EmitError("verification_session_id and code are required", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	ctx := context.Background()

	userID, credType, credValue, _, err := sessions.GetVerificationSession(ctx, req.VerificationSessionID)
	if err != nil {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	if userID != claims.UserID {
		msg.Respond(types.EmitError("Invalid session", types.NoErrors))
		return
	}

	ok, err := sessions.VerifyVerificationCode(ctx, req.VerificationSessionID, claims.UserID.String(), req.Code)
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

	if err := utils.Database.Transaction(func(tx *gorm.DB) error {
		existing, _, findErr := credentials.FindUserByCredential(tx, credType, credValue)
		if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
			return findErr
		}

		if existing != nil && existing.ID != claims.UserID {
			return errors.New("email already in use")
		}

		cred, upsertErr := credentials.UpsertCredential(tx, claims.UserID, credType, credValue)
		if upsertErr != nil {
			return upsertErr
		}

		return tx.Model(cred).Update("verified", true).Error
	}); err != nil {
		if err.Error() == "email already in use" {
			msg.Respond(types.EmitError("Email already in use", types.NoErrors))
		} else {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
		}

		return
	}

	_ = sessions.DeleteVerificationCode(ctx, req.VerificationSessionID)
	_ = sessions.DeleteVerificationSession(ctx, req.VerificationSessionID)

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
