package auth

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
	"openauth/worker/utils/sender"
	"openauth/worker/utils/sessions"

	"gorm.io/gorm"
)

type FindOrCreateResult struct {
	AccessToken  string
	RefreshToken string
	TFARequired  bool
	TFASessionID string
	TFAMethod    string
}

func FindOrCreateByCredential(credType, value string, bypassTFA bool, scope, authSessionID string) (*FindOrCreateResult, error) {
	ctx := context.Background()

	user, _, err := credentials.FindUserByCredential(utils.Database, credType, value)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("internal error")
	}

	if user == nil {
		newUser := models.User{}
		if err := utils.Database.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&newUser).Error; err != nil {
				return err
			}

			cred, err := credentials.UpsertCredential(tx, newUser.ID, credType, value)
			if err != nil {
				return err
			}

			return tx.Model(cred).Update("verified", true).Error
		}); err != nil {
			return nil, errors.New("internal error")
		}

		user = &newUser
	}

	if user.Status != "active" {
		return nil, errors.New("account blocked")
	}

	if !bypassTFA && user.TfaMethod != "none" {
		tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, 5*time.Minute, authSessionID)
		if err != nil {
			return nil, errors.New("internal error")
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

		return &FindOrCreateResult{
			TFARequired:  true,
			TFASessionID: tfaSessionID,
			TFAMethod:    user.TfaMethod,
		}, nil
	}

	sessionID, err := sessions.GenerateSessionID()
	if err != nil {
		return nil, errors.New("internal error")
	}

	accessToken, err := sessions.GenerateAccessToken(user.ID, sessionID, scope)
	if err != nil {
		return nil, errors.New("internal error")
	}

	refreshToken, err := sessions.GenerateRefreshToken(user.ID, sessionID, scope)
	if err != nil {
		return nil, errors.New("internal error")
	}

	if err := sessions.SaveSession(ctx, sessionID, user.ID, time.Duration(utils.Config.JWT.RefreshTokenTTL)*time.Second); err != nil {
		return nil, errors.New("internal error")
	}

	return &FindOrCreateResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
