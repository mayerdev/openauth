package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,password"`
}

func Login(msg *nats.Msg) {
	var req LoginRequest

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

	user, _, err := credentials.FindUserByCredential(utils.Database, credentials.CredentialTypeEmail, req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			msg.Respond(types.EmitError("Invalid credentials", types.NoErrors))
			return
		}

		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if !utils.CheckPassword(req.Password, user.Password) {
		msg.Respond(types.EmitError("Invalid credentials", types.NoErrors))
		return
	}

	if user.Status != "active" {
		msg.Respond(types.EmitError("Account blocked", types.NoErrors))
		return
	}

	ctx := context.Background()

	if user.TfaMethod != "none" {
		tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, 5*time.Minute)
		if err != nil {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
			return
		}

		data, _ := json.Marshal(TfaRequiredResult{
			TfaRequired:  true,
			TfaSessionID: tfaSessionID,
			TfaMethod:    user.TfaMethod,
			ExpiresIn:    300,
		})
		msg.Respond(data)
		return
	}

	sessionID, err := sessions.GenerateSessionID()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	accessToken, err := sessions.GenerateAccessToken(user.ID, sessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(user.ID, sessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if err := sessions.SaveSession(ctx, sessionID, user.ID, time.Duration(utils.Config.JWT.RefreshTokenTTL)*time.Second); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	msg.Respond(data)
}
