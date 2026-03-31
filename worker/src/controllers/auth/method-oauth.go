package auth

import (
	"encoding/json"

	"openauth/worker/utils/credentials"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

type OAuthMethodRequest struct {
	Provider   string `json:"provider"    validate:"required"`
	ProviderID string `json:"provider_id" validate:"required"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Scope      string `json:"scope"`
}

func OAuthMethod(msg *nats.Msg) {
	var req OAuthMethodRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return
	}

	if req.Provider == "" || req.ProviderID == "" {
		msg.Respond(types.EmitError("provider and provider_id are required", types.NoErrors))
		return
	}

	result, err := FindOrCreateByCredential(
		credentials.CredentialTypeOAuth(req.Provider),
		req.ProviderID,
		false,
		req.Scope,
	)

	if err != nil {
		msg.Respond(types.EmitError(err.Error(), types.NoErrors))
		return
	}

	if result.TFARequired {
		data, _ := json.Marshal(TfaRequiredResult{
			TfaRequired:  true,
			TfaSessionID: result.TFASessionID,
			TfaMethod:    result.TFAMethod,
			ExpiresIn:    300,
		})
		msg.Respond(data)
		return
	}

	data, _ := json.Marshal(AuthResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	})
	msg.Respond(data)
}
