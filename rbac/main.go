package rbac

import (
	"encoding/json"
	"errors"
)

var RoleNotFoundError = errors.New("role not found")

type Permission map[string][]string // Map of resource to its allowed operations

type Role struct {
	Permissions Permission `json:"permissions"`
}

type RBACPolicy struct {
	Roles map[string]Role `json:"roles"`
}

func (p RBACPolicy) CheckPermission(role, resource, operation string) (bool, error) {
	r, ok := p.Roles[role]
	if !ok {
		return false, RoleNotFoundError
	}

	ops, ok := r.Permissions[resource]
	if !ok {
		return false, nil
	}

	for _, op := range ops {
		if op == operation {
			return true, nil
		}
	}

	return false, nil
}

// New creates a new RBACPolicy from the given JSON data.
func New(data []byte) (RBACPolicy, error) {
	var policy RBACPolicy
	err := json.Unmarshal(data, &policy)
	if err != nil {
		return RBACPolicy{}, err
	}
	return policy, nil
}
