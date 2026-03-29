package roles

type AssignRoleRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Role   string `json:"role"    validate:"required"`
}

type RevokeRoleRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Role   string `json:"role"    validate:"required"`
}

type ListRolesRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

type ListRolesResult struct {
	Roles []string `json:"roles"`
}

type CheckPermissionRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Object string `json:"object"  validate:"required"`
	Action string `json:"action"  validate:"required"`
}

type CheckPermissionResult struct {
	Allowed bool `json:"allowed"`
}

type AddPolicyRequest struct {
	Role   string `json:"role"   validate:"required"`
	Object string `json:"object" validate:"required"`
	Action string `json:"action" validate:"required"`
}

type RemovePolicyRequest struct {
	Role   string `json:"role"   validate:"required"`
	Object string `json:"object" validate:"required"`
	Action string `json:"action" validate:"required"`
}

type OkResult struct {
	Ok bool `json:"ok"`
}
