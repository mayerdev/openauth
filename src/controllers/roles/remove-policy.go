package roles

import (
	"encoding/json"

	casbinutil "openauth/utils/casbin"
	"openauth/utils/types"

	"github.com/nats-io/nats.go"
)

func RemovePolicy(msg *nats.Msg) {
	var req RemovePolicyRequest
	if !bind(msg, &req) {
		return
	}

	if _, err := casbinutil.Enforcer.RemovePolicy(req.Role, req.Object, req.Action); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(OkResult{Ok: true})
	msg.Respond(data)
}
