#!/bin/bash
`rm -rf keys/`
echo "Enter CA CN"
read CaCN
echo "Enter Server CN"
read ServerCN
`mkdir -p ./keys/ca/private`
`mkdir -p ./keys/client/private`
`mkdir -p ./keys/server/private`
`openssl req \
-x509 \
-nodes \
-days 3650 \
-newkey rsa:4096 \
-keyout keys/ca/private/ca_key.pem \
-out keys/ca/ca_cert.pem \
-subj "/C=RU/ST=SPB State/L=SPB City/O=SPSTU Inc./CN=$CaCN"`
wait
`openssl genrsa -out keys/server/private/server_key.pem 4096`
wait
`openssl req -new \
-key keys/server/private/server_key.pem \
-out keys/server/server.csr \
-subj "/C=RU/ST=SPB State/L=SPB City/O=SPSTU Inc./CN=$ServerCN"`
wait
`openssl x509 -req -days 1460 -in keys/server/server.csr \
-CA keys/ca/ca_cert.pem -CAkey keys/ca/private/ca_key.pem \
-CAcreateserial -out keys/server/server_cert.pem`