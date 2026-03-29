package casbin

import (
	"fmt"

	"openauth/utils"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

const rbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eff == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

var Enforcer *casbin.Enforcer

func Init() {
	adapter, err := gormadapter.NewAdapterByDB(utils.Database)
	if err != nil {
		panic(fmt.Sprintf("Failed to init Casbin adapter: %v", err))
	}

	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse Casbin model: %v", err))
	}

	Enforcer, err = casbin.NewEnforcer(m, adapter)
	if err != nil {
		panic(fmt.Sprintf("Failed to create Casbin enforcer: %v", err))
	}
}
