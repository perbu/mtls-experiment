package rbac

import (
	// ... other imports
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/gin-gonic/gin"
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
	policy := mockPolicy()
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
}

func TestGinMiddlewareForbidden(t *testing.T) {
	policy := mockPolicy()
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
}

func TestStdlibMiddleware(t *testing.T) {
	policy := mockPolicy()
	middleware := policy.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.TLS = mockCertificate("api1")

	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, but got %d", http.StatusOK, w.Code)
	}
}

func TestStdlibMiddlewareForbidden(t *testing.T) {
	policy := mockPolicy()
	middleware := policy.WithMiddleware(func(w http.ResponseWriter, r *http.Request) {})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/users", nil)
	r.TLS = mockCertificate("api2")

	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, but got %d", http.StatusForbidden, w.Code)
	}
}
