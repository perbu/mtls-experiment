package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

func main() {
	clientCertPath := "certs/client2.crt"
	clientKeyPath := "certs/client2.key"
	caCertPath := "certs/ca.crt"

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		fmt.Printf("Error loading client certificate: %v\n", err)
		return
	}

	// Load CA cert
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Printf("Error reading CA cert: %v\n", err)
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client with mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Make a few API calls
	response, err := client.Get("https://localhost:8443/users")
	if err != nil {
		fmt.Printf("Error making GET request to /users: %v\n", err)
		return
	}
	err = response.Body.Close()
	if err != nil {
		fmt.Printf("Error closing response body: %v\n", err)
		return
	}
	fmt.Println("GET /users response:", response.Status)

	// Create a user, just give it a empty JSON body:

	response, err = client.Post("https://localhost:8443/users", "application/json", nil)
	if err != nil {
		fmt.Printf("Error making POST request to /users: %v\n", err)
		return
	}
	err = response.Body.Close()
	if err != nil {
		fmt.Printf("Error closing response body: %v\n", err)
		return
	}
	fmt.Println("POST /users response:", response.Status)

	response, err = client.Get("https://localhost:8443/products")
	if err != nil {
		fmt.Printf("Error making GET request to /products: %v\n", err)
		return
	}
	err = response.Body.Close()
	if err != nil {
		fmt.Printf("Error closing response body: %v\n", err)
		return
	}
	fmt.Println("/products response:", response.Status)
}
