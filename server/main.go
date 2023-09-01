package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"github.com/gin-gonic/gin"
	"github.com/perbu/mtls-experiment/rbac"
	"io/ioutil"
	"net/http"
	"strings"
)

//go:embed rbac.json
var rbacPolicy []byte

func main() {
	r := gin.Default()

	// Load RBAC policy (for example, from a predefined JSON data)
	data := []byte(`...`) // your RBAC JSON policy here
	policy, _ := rbac.New(data)

	// Setup middleware
	r.Use(RBACMiddleware(policy))

	r.GET("/users", getUsers)
	r.GET("/products", getProducts)

	// mTLS configuration
	serverCert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
	clientCAPool := x509.NewCertPool()
	caCert, _ := ioutil.ReadFile("ca.crt")
	clientCAPool.AppendCertsFromPEM(caCert)

	serverTLSConfig := &tls.Config{
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{
			serverCert,
		},
	}

	r.RunTLS(":8443", "", "", serverTLSConfig)
}

func RBACMiddleware(policy rbac.RBACPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientCN := extractCNFromCert(c.Request)
		if clientCN == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		hasPermission, _ := policy.CheckPermission(clientCN, c.Request.URL.Path, c.Request.Method)
		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			return
		}

		c.Next()
	}
}

func extractCNFromCert(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return strings.ToLower(r.TLS.PeerCertificates[0].Subject.CommonName)
	}
	return ""
}

func getUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "All Users"})
}

func getProducts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "All Products"})
}
