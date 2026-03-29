package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"openauth/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ErrTokenExpired = jwt.ErrTokenExpired

type TokenClaims struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID string    `json:"session_id"`
	jwt.RegisteredClaims
}

func GenerateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func GenerateAccessToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := TokenClaims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(utils.Config.JWT.AccessTokenTTL) * time.Second)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(utils.Config.JWT.Secret))
}

func GenerateRefreshToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := TokenClaims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(utils.Config.JWT.RefreshTokenTTL) * time.Second)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(utils.Config.JWT.RefreshSecret))
}

func VerifyAccessToken(tokenStr string) (*TokenClaims, error) {
	return parseToken(tokenStr, utils.Config.JWT.Secret)
}

func VerifyRefreshToken(tokenStr string) (*TokenClaims, error) {
	return parseToken(tokenStr, utils.Config.JWT.RefreshSecret)
}

func parseToken(tokenStr, secret string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
