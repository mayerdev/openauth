package roles

import (
	"encoding/json"

	casbinutil "openauth/utils/casbin"
	"openauth/utils/types"

	"github.com/nats-io/nats.go"
)

func ListRoles(msg *nats.Msg) {
	var req ListRolesRequest
	if !bind(msg, &req) {
		return
	}

	roleList, err := casbinutil.Enforcer.GetRolesForUser(req.UserID)
	if err != nil {
		msg.Respond(types.EmitError("Internal error", types.NoErrors))
		return
	}

	if roleList == nil {
		roleList = []string{}
	}

	data, _ := json.Marshal(ListRolesResult{Roles: roleList})
	msg.Respond(data)
}
