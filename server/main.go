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
)

func main() {
	r := gin.Default()

	// Load RBAC policy from "policy.json":

	policy, err := rbac.NewFromFile("policy.json", nil)
	if err != nil {
		log.Fatalf("Error loading RBAC policy: %v\n", err)
	}

	// Setup middleware
	r.Use(policy.GinMiddleware())

	r.GET("/users", getUsers)
	r.PUT("/users", putUsers)
	r.POST("/users", postUsers)
	r.DELETE("/users", deleteUsers)
	r.GET("/products", getProducts)
	r.PUT("/products", putProducts)
	r.POST("/products", postProducts)
	r.DELETE("/products", deleteProducts)

	// mTLS configuration
	serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatalf("Error loading server certificate: %v\n", err)
	}
	clientCAPool := x509.NewCertPool()
	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatalf("Error reading CA cert: %v\n", err)
	}
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
