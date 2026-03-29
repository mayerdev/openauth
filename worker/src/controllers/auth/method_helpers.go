package auth

import (
	"context"
	"errors"
	"time"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/credentials"
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

func FindOrCreateByCredential(credType, value string, bypassTFA bool) (*FindOrCreateResult, error) {
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

			_, err := credentials.UpsertCredential(tx, newUser.ID, credType, value)
			return err
		}); err != nil {
			return nil, errors.New("internal error")
		}

		user = &newUser
	}

	if user.Status != "active" {
		return nil, errors.New("account blocked")
	}

	if !bypassTFA && user.TfaMethod != "none" {
		tfaSessionID, err := sessions.CreateTfaSession(ctx, user.ID, user.TfaMethod, 5*time.Minute)
		if err != nil {
			return nil, errors.New("internal error")
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

	accessToken, err := sessions.GenerateAccessToken(user.ID, sessionID)
	if err != nil {
		return nil, errors.New("internal error")
	}

	refreshToken, err := sessions.GenerateRefreshToken(user.ID, sessionID)
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
