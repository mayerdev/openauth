package roles

import (
	"encoding/json"
	"errors"

	"openauth/worker/utils"
	"openauth/worker/utils/types"

	"github.com/go-playground/validator/v10"
	"github.com/nats-io/nats.go"
)

func bind(msg *nats.Msg, dst any) bool {
	if err := json.Unmarshal(msg.Data, dst); err != nil {
		msg.Respond(types.EmitError("Invalid request body", types.NoErrors))
		return false
	}

	if err := utils.Validator.Struct(dst); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			fieldErrors := make([]types.Error, len(ve))
			for i, fe := range ve {
				fieldErrors[i] = types.Error{Reason: fe.Field(), Message: fe.Tag()}
			}

			msg.Respond(types.EmitError("Validation error", fieldErrors))
			return false
		}

		msg.Respond(types.EmitError("Validation error", types.NoErrors))
		return false
	}

	return true
}
