package auth

import (
	"encoding/json"

	"openauth/worker/models"
	"openauth/worker/utils"
	"openauth/worker/utils/sessions"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

var validTfaMethods = map[string]bool{
	"none":  true,
	"email": true,
	"phone": true,
	"totp":  true,
}

type TfaMethodGetRequest struct {
	AccessToken string `json:"access_token"`
}

type TfaMethodSetRequest struct {
	AccessToken string `json:"access_token"`
	Method      string `json:"method"`
}

func TfaMethodGet(msg *nats.Msg) {
	var req TfaMethodGetRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.AccessToken == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Unauthorized", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]string{"method": user.TfaMethod})
	msg.Respond(data)
}

func TfaMethodSet(msg *nats.Msg) {
	var req TfaMethodSetRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.AccessToken == "" {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	claims, err := sessions.VerifyAccessToken(req.AccessToken)
	if err != nil {
		msg.Respond(types.EmitError("Unauthorized", types.NoErrors))
		return
	}

	if !validTfaMethods[req.Method] {
		msg.Respond(types.EmitError("Invalid method", types.NoErrors))
		return
	}

	var user models.User
	if err := utils.Database.First(&user, "id = ?", claims.UserID).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if req.Method == "totp" && user.TfaSecret == nil {
		msg.Respond(types.EmitError("TOTP not configured", types.NoErrors))
		return
	}

	if err := utils.Database.Model(&user).Update("tfa_method", req.Method).Error; err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(map[string]bool{"ok": true})
	msg.Respond(data)
}
