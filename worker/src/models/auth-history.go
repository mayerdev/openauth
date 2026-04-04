package models

import (
	"time"

	"github.com/google/uuid"
)

type AuthHistory struct {
	ID        uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	SessionID string    `gorm:"not null"`
	Method    string    `gorm:"not null"`
	UserAgent string
	IPAddress string
	CreatedAt time.Time
}
