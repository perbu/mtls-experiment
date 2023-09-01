package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

var RoleNotFoundError = errors.New("role not found")

type Permission map[string][]string // Map of resource to its allowed operations

type Role struct {
	Permissions Permission `json:"permissions"`
}

type RBACPolicy struct {
	Roles  map[string]Role `json:"roles"`
	logger *slog.Logger
}

func (policy RBACPolicy) CheckPermission(role, resource, operation string) (bool, error) {
	r, ok := policy.Roles[role]
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
func New(data []byte, logger *slog.Logger) (RBACPolicy, error) {
	var policy RBACPolicy
	err := json.Unmarshal(data, &policy)
	if err != nil {
		return RBACPolicy{}, fmt.Errorf("json.Unmarshal: %w", err)
	}
	policy.logger = logger
	return policy, nil
}

// NewFromFile reads the policy from a file and creates a new RBACPolicy.
func NewFromFile(file string, logger *slog.Logger) (RBACPolicy, error) {
	pBytes, err := os.ReadFile(file)
	if err != nil {
		return RBACPolicy{}, fmt.Errorf("os.ReadFile: %w", err)
	}
	return New(pBytes, logger)
}

// Dump returns the JSON representation of the policy as bytes, pretty-printed.
func (policy RBACPolicy) Dump() ([]byte, error) {
	return json.MarshalIndent(policy, "", "  ")
}
