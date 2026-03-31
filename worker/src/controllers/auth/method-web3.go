package auth

import (
	"encoding/json"
	"strings"

	"openauth/worker/utils/credentials"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

type Web3MethodRequest struct {
	Address string `json:"address" validate:"required"`
	Scope   string `json:"scope"`
}

func Web3Method(msg *nats.Msg) {
	var req Web3MethodRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Address == "" {
		msg.Respond(types.EmitError("address is required", types.NoErrors))
		return
	}

	result, err := FindOrCreateByCredential(
		credentials.CredentialTypeWeb3,
		strings.ToLower(req.Address),
		true,
		req.Scope,
	)

	if err != nil {
		msg.Respond(types.EmitError(err.Error(), types.NoErrors))
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	})
	msg.Respond(data)
}
