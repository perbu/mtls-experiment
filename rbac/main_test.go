package rbac

import (
	"errors"
	"testing"
)

func mockPolicy() RBACPolicy {
	return RBACPolicy{
		Roles: map[string]Role{
			"api1": {
				Permissions: Permission{
					"/users":    {"GET", "PUT", "POST", "DELETE"},
					"/products": {"GET", "PUT"},
				},
			},
			"api2": {
				Permissions: Permission{
					"/users": {"GET"},
				},
			},
		},
	}
}

func TestCheckPermission(t *testing.T) {
	policy := mockPolicy()

	tests := []struct {
		role      string
		resource  string
		operation string
		expected  bool
		err       error
	}{
		{"api1", "/users", "GET", true, nil},
		{"api1", "/users", "DELETE", true, nil},
		{"api1", "/products", "POST", false, nil},
		{"api2", "/users", "GET", true, nil},
		{"api2", "/users", "DELETE", false, nil},
		{"api3", "/users", "PUT", false, errors.New("role not found")},
	}

	for _, tt := range tests {
		result, err := policy.CheckPermission(tt.role, tt.resource, tt.operation)
		if result != tt.expected || (err != nil && err.Error() != tt.err.Error()) {
			t.Errorf("For role=%s, resource=%s, and operation=%s, expected %v (error: %v) but got %v (error: %v)",
				tt.role, tt.resource, tt.operation, tt.expected, tt.err, result, err)
		}
	}
}

func TestLoadRBACPolicyFromBytes(t *testing.T) {
	data := []byte(`{
		"roles": {
			"api1": {
				"permissions": {
					"/users": ["GET", "PUT", "POST", "DELETE"],
					"/products": ["GET", "PUT"]
				}
			},
			"api2": {
				"permissions": {
					"/users": ["GET"]
				}
			}
		}
	}`)

	policy, err := New(data)
	if err != nil {
		t.Fatal(err)
	}

	// Simple validation for the loaded policy
	if _, exists := policy.Roles["api1"]; !exists {
		t.Error("Expected role api1 to exist in the loaded policy.")
	}
	if perms, ok := policy.Roles["api1"].Permissions["/users"]; !ok || len(perms) != 4 {
		t.Error("Expected role api1 to have 4 permissions for /users.")
	}
}

func TestInvalidPolicy(t *testing.T) {
	data := []byte(`{
		"roles": {
			"api1": {
				"permissions": {
					"/users": ["GET", "PUT", "POST", "DELETE"],
					"/products": ["GET", "PUT"]
				}
			},
			"api2": {
				"permissions": {
					"/users": ["GET"]
				}
			}
		}
	`)
	_, err := New(data)
	if err == nil {
		t.Error("Expected error for invalid policy.")
	}
}
