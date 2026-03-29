package auth

import (
	"context"
	"encoding/json"

	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

type LogoutRequest struct {
	AccessToken string `json:"access_token"`
}

func Logout(msg *nats.Msg) {
	var req LogoutRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Invalid token", types.NoErrors))
		return
	}

	if err := sessions.DeleteSession(context.Background(), claims.SessionID); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
