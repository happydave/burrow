#!/bin/bash
# Generates the harness's test PKI into the directory given (default /pki):
# a CA, a server certificate (serverAuth), client certificates for CN 123456
# (allowlisted) and 999999 (not), and a 2048-bit DH group. RSA-2048, SHA-256.
set -eu
cd "${1:-/pki}"
cat > ext.cnf <<'X'
[srv]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
[cli]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
X
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 -subj "/CN=burrow interop CA" -keyout ca.key -out ca.crt 2>/dev/null
for n in server:srv 123456:cli 999999:cli; do
  cn=${n%%:*}; ext=${n##*:}
  openssl req -newkey rsa:2048 -nodes -subj "/O=Test/OU=Platform/CN=$cn" -keyout "$cn.key" -out "$cn.csr" 2>/dev/null
  openssl x509 -req -in "$cn.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 \
    -extfile ext.cnf -extensions "$ext" -out "$cn.crt" 2>/dev/null
done
openssl dhparam -out dh.pem 2048 2>/dev/null
chmod 644 ./*
