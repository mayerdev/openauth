package auth

import (
	"encoding/json"
	"errors"

	"openauth/models"
	"openauth/utils"
	"openauth/utils/credentials"
	"openauth/utils/sessions"
	"openauth/utils/types"

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,password"`
}

func Register(msg *nats.Msg) {
	var req RegisterRequest

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

	existing, _, err := credentials.FindUserByCredential(utils.Database, credentials.CredentialTypeEmail, req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if existing != nil {
		msg.Respond(types.EmitError("Email already taken", types.NoErrors))
		return
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.Transaction(func(tx *gorm.DB) error {
		user = models.User{Password: hash}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}

		_, err := credentials.UpsertCredential(tx, user.ID, credentials.CredentialTypeEmail, req.Email)

		return err
	}); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))

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

	data, _ := json.Marshal(AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	msg.Respond(data)
}
