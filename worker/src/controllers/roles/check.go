package roles

import (
	"encoding/json"

	casbinutil "openauth/worker/utils/casbin"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

func CheckPermission(msg *nats.Msg) {
	var req CheckPermissionRequest
	if !bind(msg, &req) {
		return
	}

	allowed, err := casbinutil.Enforcer.Enforce(req.UserID, req.Object, req.Action)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(CheckPermissionResult{Allowed: allowed})
	msg.Respond(data)
}
