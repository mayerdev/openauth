package credentials

import (
	"openauth/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CredentialType = string

const (
	CredentialTypeEmail CredentialType = "email"
	CredentialTypePhone CredentialType = "phone"
)

var SupportedCredentialTypes = []CredentialType{
	CredentialTypeEmail,
	CredentialTypePhone,
}

type CredentialPolicy struct {
	PasswordRequired bool
	BypassTFA        bool
}

var CredentialPolicies = map[CredentialType]CredentialPolicy{
	CredentialTypeEmail: {PasswordRequired: true, BypassTFA: false},
	CredentialTypePhone: {PasswordRequired: true, BypassTFA: false},
}

func FindUserByCredential(db *gorm.DB, credType, value string) (*models.User, []models.UserCredential, error) {
	var cred models.UserCredential
	if err := db.Where("type = ? AND value = ?", credType, value).First(&cred).Error; err != nil {
		return nil, nil, err
	}

	var user models.User
	if err := db.First(&user, "id = ?", cred.UserID).Error; err != nil {
		return nil, nil, err
	}

	var allCreds []models.UserCredential
	if err := db.Where("user_id = ?", cred.UserID).Find(&allCreds).Error; err != nil {
		return nil, nil, err
	}

	return &user, allCreds, nil
}

func UpsertCredential(db *gorm.DB, userID uuid.UUID, credType, value string) (*models.UserCredential, error) {
	var cred models.UserCredential

	result := db.Where(models.UserCredential{UserID: userID, Type: credType}).
		Assign(models.UserCredential{Value: value}).
		FirstOrCreate(&cred)

	if result.Error != nil {
		return nil, result.Error
	}

	return &cred, nil
}
