package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sender"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Method        string `json:"method"`
	Email         string `json:"email"`
	Phone         string `json:"phone"`
	Password      string `json:"password" validate:"required,password"`
	Scope         string `json:"scope"`
	AuthSessionID string `json:"auth_session_id"`
}

func Login(msg *nats.Msg) {
	var req LoginRequest

	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Method == "" {
		req.Method = "email"
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

	var (
		credType  string
		credValue string
	)

	switch req.Method {
	case "phone":
		if !utils.Config.Auth.EnablePhone {
			msg.Respond(types.EmitError("Phone auth is disabled", types.NoErrors))
			return
		}

		phone, err := credentials.NormalizePhone(req.Phone)
		if err != nil {
			msg.Respond(types.EmitError("Invalid phone number", types.NoErrors))
			return
		}
		credType = credentials.CredentialTypePhone
		credValue = phone
	default:
		if !utils.Config.Auth.EnableEmail {
			msg.Respond(types.EmitError("Email auth is disabled", types.NoErrors))
			return
		}

		if req.Email == "" {
			msg.Respond(types.EmitError("Email is required", types.NoErrors))
			return
		}
		credType = credentials.CredentialTypeEmail
		credValue = req.Email
	}

	user, allCreds, err := credentials.FindUserByCredential(utils.Database, credType, credValue)
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
		tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, 5*time.Minute, req.AuthSessionID)
		if err != nil {
			msg.Respond(types.EmitError("Internal error", types.NoErrors))
			return
		}

		if user.TfaMethod == "email" || user.TfaMethod == "phone" {
			code := fmt.Sprintf("%06d", rand.Intn(1000000))
			_ = sessions.StoreTfaCode(ctx, tfaSessionID, user.ID, code, user.TfaMethod, 5*time.Minute)
			sendType := "sms"
			notifTo := ""

			if user.TfaMethod == "email" {
				sendType = "email"
				notifTo = req.Email
			} else {
				for _, c := range allCreds {
					if c.Type == credentials.CredentialTypePhone {
						notifTo = c.Value
						break
					}
				}
			}

			if notifTo != "" {
				sender.SendCode(utils.Nats, sendType, notifTo, code)
			}
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

	accessToken, err := sessions.GenerateAccessToken(user.ID, sessionID, req.Scope)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(user.ID, sessionID, req.Scope)
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
