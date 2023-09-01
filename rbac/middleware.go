package rbac

import (
	"context"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"strings"
)

func (policy RBACPolicy) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientCN := extractCNFromCert(c.Request)
		if clientCN == "" {
			policy.log(slog.LevelError, "No client certificate found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		hasPermission, err := policy.CheckPermission(clientCN, c.Request.URL.Path, c.Request.Method)
		if err != nil {
			policy.log(slog.LevelError, "Error checking permission: %v", err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}
		if !hasPermission {
			policy.log(slog.LevelError, "Client %s does not have permission to %s %s", clientCN, c.Request.Method, c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}
		c.Next()
	}
}

func (policy RBACPolicy) stdlibMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientCN := extractCNFromCert(r)
		if clientCN == "" {
			policy.log(slog.LevelError, "No client certificate found")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		hasPermission, err := policy.CheckPermission(clientCN, r.URL.Path, r.Method)
		if err != nil {
			policy.log(slog.LevelError, "Error checking permission: %v", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !hasPermission {
			policy.log(slog.LevelError, "Client %s does not have permission to %s %s", clientCN, r.Method, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (policy RBACPolicy) WithMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return policy.stdlibMiddleware(handler)
}

func extractCNFromCert(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return strings.ToLower(r.TLS.PeerCertificates[0].Subject.CommonName)
	}
	return ""
}

func (policy RBACPolicy) log(level slog.Level, msg string, args ...any) {
	if policy.logger == nil {
		return
	}
	policy.logger.Log(context.Background(), level, msg, args...)
}
