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

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Method   string `json:"method"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password" validate:"required,password"`
}

func Register(msg *nats.Msg) {
	var req RegisterRequest

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

	switch req.Method {
	case "phone":
		registerPhone(msg, &req)
	default:
		registerEmail(msg, &req)
	}
}

func registerEmail(msg *nats.Msg, req *RegisterRequest) {
	if req.Email == "" {
		msg.Respond(types.EmitError("Email is required", types.NoErrors))
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

	if role := utils.Config.Auth.DefaultRole; role != "" {
		_, _ = casbinutil.Enforcer.AddRoleForUser(user.ID.String(), role)
	}

	ctx := context.Background()
	codeTTL := time.Duration(utils.Config.Verification.CodeTTL) * time.Second

	verificationSessionID, err := sessions.CreateVerificationSession(ctx, user.ID, credentials.CredentialTypeEmail, req.Email, codeTTL)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	if err := sessions.StoreVerificationCode(ctx, verificationSessionID, user.ID, code, credentials.CredentialTypeEmail, codeTTL); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	_ = sessions.CheckAndSetResendInterval(ctx, verificationSessionID)

	sender.SendCode(utils.Nats, "email", req.Email, code)

	data, _ := json.Marshal(VerificationRequiredResult{
		VerificationRequired:  true,
		VerificationSessionID: verificationSessionID,
		VerificationMethod:    "email",
	})
	msg.Respond(data)
}

func registerPhone(msg *nats.Msg, req *RegisterRequest) {
	phone, err := credentials.NormalizePhone(req.Phone)
	if err != nil {
		msg.Respond(types.EmitError("Invalid phone number", types.NoErrors))
		return
	}

	existing, _, err := credentials.FindUserByCredential(utils.Database, credentials.CredentialTypePhone, phone)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}
	if existing != nil {
		msg.Respond(types.EmitError("Phone already taken", types.NoErrors))
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
		_, err := credentials.UpsertCredential(tx, user.ID, credentials.CredentialTypePhone, phone)
		return err
	}); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if role := utils.Config.Auth.DefaultRole; role != "" {
		_, _ = casbinutil.Enforcer.AddRoleForUser(user.ID.String(), role)
	}

	ctx := context.Background()
	codeTTL := time.Duration(utils.Config.Verification.CodeTTL) * time.Second

	verificationSessionID, err := sessions.CreateVerificationSession(ctx, user.ID, credentials.CredentialTypePhone, phone, codeTTL)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	if err := sessions.StoreVerificationCode(ctx, verificationSessionID, user.ID, code, credentials.CredentialTypePhone, codeTTL); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	_ = sessions.CheckAndSetResendInterval(ctx, verificationSessionID)

	sender.SendCode(utils.Nats, "sms", phone, code)

	data, _ := json.Marshal(VerificationRequiredResult{
		VerificationRequired:  true,
		VerificationSessionID: verificationSessionID,
		VerificationMethod:    "phone",
	})
	msg.Respond(data)
}
