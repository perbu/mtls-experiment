package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: cli <client.crt> <client.key> <ca.crt>")
		return
	}

	clientCertPath := os.Args[1]
	clientKeyPath := os.Args[2]
	caCertPath := os.Args[3]

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		fmt.Printf("Error loading client certificate: %v\n", err)
		return
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caCertPath)
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
	defer response.Body.Close()
	fmt.Println("/users response:", response.Status)

	response, err = client.Get("https://localhost:8443/products")
	if err != nil {
		fmt.Printf("Error making GET request to /products: %v\n", err)
		return
	}
	defer response.Body.Close()
	fmt.Println("/products response:", response.Status)
}
