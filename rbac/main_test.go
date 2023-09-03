package rbac

import (
	"os"
	"testing"
)

func mockPolicy() RBACPolicy {
	return RBACPolicy{
		Roles: map[string]Role{
			"api1": {
				Permissions: Permission{
					"/users":    {"*"},
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
func (policy RBACPolicy) withLogger(l logger) RBACPolicy {
	policy.logger = l
	return policy
}

func TestCheckPermission(t *testing.T) {
	policy := mockPolicy()

	tests := []struct {
		name      string
		role      string
		resource  string
		operation string
		expected  bool
		err       error
	}{
		{"Api1 GET users with correct case", "api1", "/users", "GET", true, nil},
		{"Api1 GET users with lowercase", "api1", "/users", "get", true, nil},
		{"Api1 GET users with capitalized case", "api1", "/users", "Get", true, nil},
		{"Api1 POST users", "api1", "/users", "POST", true, nil},
		{"Api1 PUT users", "api1", "/users", "PUT", true, nil},
		{"Api1 DELETE users", "api1", "/users", "DELETE", true, nil},
		{"Api1 GET unknown resource", "api1", "/unknown", "GET", false, nil},
		{"Api1 POST products", "api1", "/products", "POST", false, nil},
		{"Api2 GET users", "api2", "/users", "GET", true, nil},
		{"Api2 DELETE users", "api2", "/users", "DELETE", false, nil},
		{"Api3 PUT users with role not found", "api3", "/users", "PUT", false, RoleNotFoundError},
		{"Empty role GET users", "", "/users", "GET", false, RoleNotFoundError},
	}
	for _, tt := range tests {
		result, err := policy.CheckPermission(tt.role, tt.resource, tt.operation)
		if result != tt.expected || (err != nil && err.Error() != tt.err.Error()) {
			t.Errorf("%s: For role=%s, resource=%s, and operation=%s, success %v (error: %v) but got %v (error: %v)",
				tt.name, tt.role, tt.resource, tt.operation, tt.expected, tt.err, result, err)
		}
	}
}

func testPolicy1() []byte {
	return []byte(`{
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
}

func TestLoadRBACPolicyFromBytes(t *testing.T) {
	policy, err := New(testPolicy1())
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
	// dump the policy to stdout
	bytes, err := policy.Dump()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes) < 10 {
		t.Error("Expected policy to be dumped as JSON.")
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

func TestNewFromFile(t *testing.T) {
	tmpFile := t.TempDir() + "/policy.json"
	err := os.WriteFile(tmpFile, testPolicy1(), 0644)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewFromFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := policy.Roles["api1"]; !exists {
		t.Error("Expected role api1 to exist in the loaded policy.")
	}
}
