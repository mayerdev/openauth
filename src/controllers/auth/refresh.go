package auth

import (
	"encoding/json"
	"errors"

	"openauth/utils/sessions"
	"openauth/utils/types"

	"github.com/nats-io/nats.go"
)

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func Refresh(msg *nats.Msg) {
	var req RefreshRequest

	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, sessions.ErrTokenExpired) {
			msg.Respond(types.EmitError("Token expired", types.NoErrors))
			return
		}

		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	sessionID, err := sessions.GenerateSessionID()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	accessToken, err := sessions.GenerateAccessToken(claims.UserID, sessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(claims.UserID, sessionID)
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
