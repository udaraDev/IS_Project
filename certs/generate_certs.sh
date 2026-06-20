#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs
cd certs
rm -f *.key *.crt *.csr *.srl *.ext

openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
  -subj "//CN=MalwareAnalysisCA/O=ISProject/C=LK"

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "//CN=localhost/O=ISProject/C=LK"
cat > server.ext <<'EXT'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server.ext

openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "//CN=analyst-client/O=ISProject/C=LK"
cat > client.ext <<'EXT'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256 -extfile client.ext
rm -f *.csr *.ext
printf "\n✅ Certificates created in certs/\n"
