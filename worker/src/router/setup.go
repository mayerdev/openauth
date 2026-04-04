package router

import (
	"openauth/worker/controllers/auth"
	"openauth/worker/controllers/credentials"
	"openauth/worker/controllers/roles"
	"openauth/worker/utils"
)

const queueGroup = "openauth"

func Setup() {
	utils.Nats.QueueSubscribe("auth.register", queueGroup, auth.Register)
	utils.Nats.QueueSubscribe("auth.login", queueGroup, auth.Login)
	utils.Nats.QueueSubscribe("auth.tfa.verify", queueGroup, auth.TfaVerify)
	utils.Nats.QueueSubscribe("auth.token.refresh", queueGroup, auth.Refresh)
	utils.Nats.QueueSubscribe("auth.session.verify", queueGroup, auth.Verify)
	utils.Nats.QueueSubscribe("auth.logout", queueGroup, auth.Logout)
	utils.Nats.QueueSubscribe("auth.history.get", queueGroup, auth.GetHistory)
	utils.Nats.QueueSubscribe("auth.method.oauth", queueGroup, auth.OAuthMethod)
	utils.Nats.QueueSubscribe("auth.method.web3", queueGroup, auth.Web3Method)

	utils.Nats.QueueSubscribe("auth.credential.verify", queueGroup, auth.CredentialVerify)
	utils.Nats.QueueSubscribe("auth.credential.verify.resend", queueGroup, auth.CredentialVerifyResend)

	utils.Nats.QueueSubscribe("auth.totp.start", queueGroup, auth.TotpStart)
	utils.Nats.QueueSubscribe("auth.totp.confirm", queueGroup, auth.TotpConfirm)
	utils.Nats.QueueSubscribe("auth.totp.unlink", queueGroup, auth.TotpUnlink)
	utils.Nats.QueueSubscribe("auth.tfa.method.get", queueGroup, auth.TfaMethodGet)
	utils.Nats.QueueSubscribe("auth.tfa.method.set", queueGroup, auth.TfaMethodSet)

	utils.Nats.QueueSubscribe("auth.credential.link.email.start", queueGroup, credentials.LinkEmailStart)
	utils.Nats.QueueSubscribe("auth.credential.link.email.confirm", queueGroup, credentials.LinkEmailConfirm)
	utils.Nats.QueueSubscribe("auth.credential.link.phone.start", queueGroup, credentials.LinkPhoneStart)
	utils.Nats.QueueSubscribe("auth.credential.link.phone.confirm", queueGroup, credentials.LinkPhoneConfirm)
	utils.Nats.QueueSubscribe("auth.credential.link.oauth", queueGroup, credentials.LinkOAuth)
	utils.Nats.QueueSubscribe("auth.credential.link.web3", queueGroup, credentials.LinkWeb3)
	utils.Nats.QueueSubscribe("auth.credential.unlink", queueGroup, credentials.UnlinkDirect)
	utils.Nats.QueueSubscribe("auth.tfa.resend", queueGroup, credentials.TfaResend)

	utils.Nats.QueueSubscribe("auth.roles.assign", queueGroup, roles.AssignRole)
	utils.Nats.QueueSubscribe("auth.roles.revoke", queueGroup, roles.RevokeRole)
	utils.Nats.QueueSubscribe("auth.roles.list", queueGroup, roles.ListRoles)
	utils.Nats.QueueSubscribe("auth.roles.check", queueGroup, roles.CheckPermission)
	utils.Nats.QueueSubscribe("auth.roles.add-policy", queueGroup, roles.AddPolicy)
	utils.Nats.QueueSubscribe("auth.roles.remove-policy", queueGroup, roles.RemovePolicy)
}
