package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"openauth/worker/utils"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

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

	ctx := context.Background()

	exists, err := sessions.SessionExists(ctx, claims.SessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}
	if !exists {
		msg.Respond(types.EmitError("Session expired", types.NoErrors))
		return
	}

	_ = sessions.DeleteSession(ctx, claims.SessionID)

	newSessionID, err := sessions.GenerateSessionID()
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	accessToken, err := sessions.GenerateAccessToken(claims.UserID, newSessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	refreshToken, err := sessions.GenerateRefreshToken(claims.UserID, newSessionID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if err := sessions.SaveSession(ctx, newSessionID, claims.UserID, time.Duration(utils.Config.JWT.RefreshTokenTTL)*time.Second); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	msg.Respond(data)
}
