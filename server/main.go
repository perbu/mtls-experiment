package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"github.com/gin-gonic/gin"
	"github.com/perbu/mtls-experiment/rbac"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:embed rbac.json
var rbacPolicy []byte

func main() {
	r := gin.Default()

	// Load RBAC policy from "policy.json":

	policy, err := rbac.NewFromFile("policy.json")
	if err != nil {
		log.Fatalf("Error loading RBAC policy: %v\n", err)
	}

	// Setup middleware
	r.Use(RBACMiddleware(policy))

	r.GET("/users", getUsers)
	r.PUT("/users", putUsers)
	r.POST("/users", postUsers)
	r.DELETE("/users", deleteUsers)
	r.GET("/products", getProducts)
	r.PUT("/products", putProducts)
	r.POST("/products", postProducts)
	r.DELETE("/products", deleteProducts)

	// mTLS configuration
	serverCert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
	clientCAPool := x509.NewCertPool()
	caCert, _ := os.ReadFile("ca.crt")
	clientCAPool.AppendCertsFromPEM(caCert)

	serverTLSConfig := &tls.Config{
		ClientCAs:  clientCAPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{
			serverCert,
		},
	}

	// Create an HTTP server with the Gin engine and our TLS configuration
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   r,
		TLSConfig: serverTLSConfig,
	}
	log.Println("Server listening on port 8443")

	// Run the server
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %s\n", err)
	}
}

func RBACMiddleware(policy rbac.RBACPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientCN := extractCNFromCert(c.Request)
		if clientCN == "" {
			log.Printf("No client certificate found\n")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		hasPermission, _ := policy.CheckPermission(clientCN, c.Request.URL.Path, c.Request.Method)
		if !hasPermission {
			log.Printf("Client %s does not have permission to %s %s\n", clientCN, c.Request.Method, c.Request.URL.Path)
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

func putUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Update Users"})
}

func postUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Create Users"})
}

func deleteUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Delete Users"})
}

func getProducts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "All Products"})
}

func putProducts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Update Products"})
}

func postProducts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Create Products"})
}

func deleteProducts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Delete Products"})
}
