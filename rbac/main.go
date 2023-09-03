package rbac

import (
	"context"
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
	logger logger
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
		// check that the operation or * is allowed:
		if op == operation || op == "*" {
			return true, nil
		}
	}
	return false, nil
}

// New creates a new RBACPolicy from the given JSON data.
func New(data []byte, options ...func(policy *RBACPolicy)) (RBACPolicy, error) {
	var policy RBACPolicy
	err := json.Unmarshal(data, &policy)
	if err != nil {
		return RBACPolicy{}, fmt.Errorf("json.Unmarshal: %w", err)
	}
	for _, option := range options {
		option(&policy)
	}
	return policy, nil
}

// NewFromFile reads the policy from a file and creates a new RBACPolicy.
func NewFromFile(file string, options ...func(policy *RBACPolicy)) (RBACPolicy, error) {
	pBytes, err := os.ReadFile(file)
	if err != nil {
		return RBACPolicy{}, fmt.Errorf("os.ReadFile: %w", err)
	}
	return New(pBytes, options...)
}

type logger interface {
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
}

// WithLogger sets the logger for the policy.
func WithLogger(logger logger) func(policy *RBACPolicy) {
	return func(policy *RBACPolicy) {
		policy.logger = logger
	}
}

// Dump returns the JSON representation of the policy as bytes, pretty-printed.
func (policy RBACPolicy) Dump() ([]byte, error) {
	return json.MarshalIndent(policy, "", "  ")
}
