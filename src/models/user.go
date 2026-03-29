package models

import "encoding/json"

type User struct {
	BaseModel
	Password       string          `json:"password"`
	Status         string          `json:"status" gorm:"default:active"`
	TfaMethod      string          `json:"tfa_method" gorm:"default:none"`
	TfaSecret      *string         `json:"-"`
	TfaBackupCodes json.RawMessage `json:"-" gorm:"type:jsonb"`
}
