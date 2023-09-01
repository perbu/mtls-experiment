#!/bin/bash

# Directory to store generated certs and keys
mkdir -p certs

# Generate Root CA
echo "Generating root CA..."
openssl genpkey -algorithm RSA -out certs/ca.key
openssl req -x509 -new -nodes -key certs/ca.key -subj "/CN=RootCA" -days 1024 -out certs/ca.crt

# Function to generate key and certificate for a given role
generate_cert_for_role() {
    local ROLE=$1

    echo "Generating cert for role $ROLE..."

    # Generate private key for the role
    openssl genpkey -algorithm RSA -out certs/${ROLE}.key

    # Generate CSR for the role
    openssl req -new -key certs/${ROLE}.key -subj "/CN=$ROLE" -out certs/${ROLE}.csr

    # Use the CA to sign the CSR, granting a cert to this role
    openssl x509 -req -in certs/${ROLE}.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/${ROLE}.crt -days 1024
}

# Generate keys and certificates for each role
for ROLE in read write readwrite; do
    generate_cert_for_role $ROLE
done

echo "All done!"
