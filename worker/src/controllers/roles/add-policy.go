package roles

import (
	"encoding/json"

	casbinutil "openauth/worker/utils/casbin"
	"openauth/worker/utils/types"

	"github.com/nats-io/nats.go"
)

func AddPolicy(msg *nats.Msg) {
	var req AddPolicyRequest
	if !bind(msg, &req) {
		return
	}

	if _, err := casbinutil.Enforcer.AddPolicy(req.Role, req.Object, req.Action); err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	data, _ := json.Marshal(OkResult{Ok: true})
	msg.Respond(data)
}
