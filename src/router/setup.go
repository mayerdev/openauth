package router

import (
	"openauth/controllers/auth"
	"openauth/controllers/roles"
	"openauth/utils"
)

const queueGroup = "openauth"

func Setup() {
	utils.Nats.QueueSubscribe("auth.register", queueGroup, auth.Register)
	utils.Nats.QueueSubscribe("auth.login", queueGroup, auth.Login)
	utils.Nats.QueueSubscribe("auth.tfa.verify", queueGroup, auth.TfaVerify)
	utils.Nats.QueueSubscribe("auth.token.refresh", queueGroup, auth.Refresh)

	utils.Nats.QueueSubscribe("auth.roles.assign", queueGroup, roles.AssignRole)
	utils.Nats.QueueSubscribe("auth.roles.revoke", queueGroup, roles.RevokeRole)
	utils.Nats.QueueSubscribe("auth.roles.list", queueGroup, roles.ListRoles)
	utils.Nats.QueueSubscribe("auth.roles.check", queueGroup, roles.CheckPermission)
	utils.Nats.QueueSubscribe("auth.roles.add-policy", queueGroup, roles.AddPolicy)
	utils.Nats.QueueSubscribe("auth.roles.remove-policy", queueGroup, roles.RemovePolicy)
}
