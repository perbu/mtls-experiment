#!/bin/bash

# Directory to store generated certs and keys
set -e
rm -rf  certs
mkdir -p certs

# Generate Root CA
echo "Generating root CA..."
openssl genpkey -algorithm RSA -out certs/ca.key
openssl req -x509 -new -nodes -key certs/ca.key -subj "/CN=RootCA" -days 1024 -out certs/ca.crt

echo dumping san config.
cat > certs/san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
countryName = Country Name (2 letter code)
countryName_default = US
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = CA
localityName = Locality Name (eg, city)
localityName_default = San Francisco
organizationalUnitName  = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Development
commonName = Common Name (eg, YOUR name)
commonName_max  = 64

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
EOF


echo "Generating server key"
openssl genpkey -algorithm RSA -out certs/server.key
echo "Generating server CSR"
openssl req -new -key certs/server.key -subj "/CN=localhost" -config certs/san.cnf -extensions v3_req -out certs/server.csr

# Sign the CSR with Root CA
echo "Signing server CSR"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 1024 -extensions v3_req -extfile certs/san.cnf
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
for ROLE in client1 client2 client3; do
    generate_cert_for_role $ROLE
done

echo "All done!"
