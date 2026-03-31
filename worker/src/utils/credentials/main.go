package credentials

import (
	"errors"
	"strings"
	"unicode"

	"openauth/worker/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func NormalizePhone(raw string) (string, error) {
	var digits strings.Builder
	for _, ch := range raw {
		if unicode.IsDigit(ch) {
			digits.WriteRune(ch)
		}
	}

	if digits.Len() < 7 {
		return "", errors.New("invalid phone number")
	}

	return "+" + digits.String(), nil
}

type CredentialType = string

const (
	CredentialTypeEmail CredentialType = "email"
	CredentialTypePhone CredentialType = "phone"
	CredentialTypeWeb3  CredentialType = "web3"
)

func CredentialTypeOAuth(provider string) CredentialType {
	return "oauth:" + provider
}

var SupportedCredentialTypes = []CredentialType{
	CredentialTypeEmail,
	CredentialTypePhone,
	CredentialTypeWeb3,
}

type CredentialPolicy struct {
	PasswordRequired bool
	BypassTFA        bool
}

var CredentialPolicies = map[CredentialType]CredentialPolicy{
	CredentialTypeEmail: {PasswordRequired: true, BypassTFA: false},
	CredentialTypePhone: {PasswordRequired: true, BypassTFA: false},
	CredentialTypeWeb3:  {PasswordRequired: false, BypassTFA: true},
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
