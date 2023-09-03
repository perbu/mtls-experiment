package rbac

import (
	"context"
	// ... other imports
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockCertificate creates a TLS connection state with a single certificate
// having the provided CN.
func mockCertificate(cn string) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: cn,
				},
			},
		},
	}
}

func TestGinMiddleware(t *testing.T) {
	l := new(mockLogger)
	policy := mockPolicy().withLogger(l)
	middleware := policy.GinMiddleware()

	// Mocking a Gin context with certificate having "api1" CN
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.TLS = mockCertificate("api1")
	c, _ := gin.CreateTestContext(w)
	c.Request = r

	// Executing middleware
	middleware(c)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, but got %d", http.StatusOK, w.Code)
	}
	if len(l.logLines) != 0 {
		t.Errorf("Expected 0 log line, but got %d", len(l.logLines))
	}
}

func TestGinBattery(t *testing.T) {
	tests := []struct {
		name      string
		role      string
		resource  string
		operation string
		success   bool
	}{
		{"Api1 GET users with correct case", "api1", "/users", "GET", true},
		{"Api1 GET users with lowercase", "api1", "/users", "get", true},
		{"Api1 GET users with capitalized case", "api1", "/users", "Get", true},
		{"Api1 POST users", "api1", "/users", "POST", true},
		{"Api1 PUT users", "api1", "/users", "PUT", true},
		{"Api1 DELETE users", "api1", "/users", "DELETE", true},
		{"Api1 GET unknown resource", "api1", "/unknown", "GET", false},
		{"Api1 POST products", "api1", "/products", "POST", false},
		{"Api2 GET users", "api2", "/users", "GET", true},
		{"Api2 DELETE users", "api2", "/users", "DELETE", false},
		{"Api3 PUT users", "api3", "/users", "PUT", false},
		{"Empty role", "", "/users", "GET", false},
	}
	l := new(mockLogger)
	policy := mockPolicy().withLogger(l)
	middleware := policy.GinMiddleware()

	for _, tt := range tests {
		l.reset()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tt.operation, tt.resource, nil)
		r.TLS = mockCertificate(tt.role)
		c, _ := gin.CreateTestContext(w)
		c.Request = r

		// Executing middleware
		middleware(c)
		switch tt.success {
		case true:
			if w.Code != http.StatusOK {
				t.Errorf("%s: Expected status %d, but got %d", tt.name, http.StatusOK, w.Code)
			}
			if len(l.logLines) != 0 {
				t.Errorf("%s: Expected 0 log line, but got %d", tt.name, len(l.logLines))
			}
		case false:
			if w.Code != http.StatusForbidden {
				t.Errorf("%s: Expected status %d, but got %d", tt.name, http.StatusForbidden, w.Code)
			}
			if len(l.logLines) != 1 {
				t.Errorf("%s: Expected 1 log line, but got %d", tt.name, len(l.logLines))
			}
		}
	}

}

func TestGinMiddlewareForbidden(t *testing.T) {
	l := new(mockLogger)
	// take the mock policy, turn it into JSON so it'll load nicely.
	policyBytes, err := mockPolicy().Dump()
	if err != nil {
		t.Fatal(err)
	}
	// create a new policy from the JSON, with the mock logger
	policy, err := New(policyBytes, WithLogger(l))
	if err != nil {
		t.Fatal(err)
	}
	middleware := policy.GinMiddleware()
	// Mocking a Gin context with certificate having "api2" CN
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users", nil)
	r.TLS = mockCertificate("api2")
	c, _ := gin.CreateTestContext(w)
	c.Request = r

	// Executing middleware
	middleware(c)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, but got %d", http.StatusForbidden, w.Code)
	}
	if len(l.logLines) != 1 {
		t.Errorf("Expected 1 log line, but got %d", len(l.logLines))
	}
}

func TestStdlibMiddleware(t *testing.T) {
	l := new(mockLogger)
	policy := mockPolicy().withLogger(l)
	middleware := policy.WithRBAC(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.TLS = mockCertificate("api1")

	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, but got %d", http.StatusOK, w.Code)
	}
	if len(l.logLines) != 0 {
		t.Errorf("Expected 0 log line, but got %d", len(l.logLines))
	}
}

func TestStdlibMiddlewareForbidden(t *testing.T) {
	l := new(mockLogger)
	policy := mockPolicy().withLogger(l)
	middleware := policy.WithRBAC(func(w http.ResponseWriter, r *http.Request) {})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users", nil)
	r.TLS = mockCertificate("api2")

	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, but got %d", http.StatusForbidden, w.Code)
	}
	if len(l.logLines) != 1 {
		t.Errorf("Expected 1 log line, but got %d", len(l.logLines))
	}
}

type mockLogLine struct {
	level slog.Level
	msg   string
	args  []any
}

type mockLogger struct {
	logLines []mockLogLine
}

func (l *mockLogger) Log(_ context.Context, level slog.Level, msg string, args ...any) {
	l.logLines = append(l.logLines, mockLogLine{level, msg, args})
}

func (l *mockLogger) reset() {
	l.logLines = make([]mockLogLine, 0)
}
