#!/bin/bash
`rm -rf keys/client`
mkdir -p keys/client/private
echo "Enter UserName"
read UserName
openssl genrsa -out keys/client/private/client_key.pem 4096
openssl req -new \
-key keys/client/private/client_key.pem \
-out keys/client/client.csr \
-subj "/C=RU/ST=SPB State/L=SPB City/O=SPSTU Inc./CN=$UserName"

openssl x509 -req -days 1460 -in keys/client/client.csr \
-CA keys/ca/ca_cert.pem -CAkey keys/ca/private/ca_key.pem \
-CAcreateserial -out keys/client/client_cert.pem

openssl pkcs12 -export -out keys/client/certificate.p12 -inkey keys/client/private/client_key.pem -in keys/client/client_cert.pem -CAfile keys/ca/ca_cert.pem