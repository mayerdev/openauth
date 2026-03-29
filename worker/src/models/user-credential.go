package models

import "github.com/google/uuid"

type UserCredential struct {
	BaseModel
	UserID           uuid.UUID `json:"user_id"`
	Type             string    `json:"type"`
	Value            string    `json:"value"`
	VerificationCode string    `json:"verification_code"`
	Verified         bool      `json:"verified" gorm:"default:false"`
}
