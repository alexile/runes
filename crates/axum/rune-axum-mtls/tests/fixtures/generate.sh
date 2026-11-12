#!/usr/bin/env bash
# Regenerates the throwaway mTLS test PKI in this directory with
# OpenSSL >= 3.4 (for `-not_before` / `-not_after`). The private keys are
# committed on purpose: they protect nothing and exist only so the tests can
# run a loopback TLS server and client. Run from anywhere:
# `bash tests/fixtures/generate.sh`.
#
# Layout (all EC P-256, valid 2025-01-01 .. 2125-01-01):
#   ca.pem / ca.key            client and server CA
#   server.pem / server.key    server leaf by ca: DNS:localhost, IP:127.0.0.1 (serverAuth)
#   client.pem / client.key    client leaf by ca: CN=alice, DNS:alice.example.com,
#                              email alice@example.com (clientAuth)
#   server-eku.pem / .key      leaf by ca with serverAuth only: CN=wrong-purpose
#   rogue-ca.pem               a CA that is not trusted by the tests
#   rogue-client.pem / .key    client leaf by rogue-ca: CN=mallory (clientAuth)
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

FROM=20250101000000Z
TO=21250101000000Z

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

ca() { # NAME SUBJECT
    key "$1.key"
    cat >"$tmp/$1.ext" <<EXT
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
    openssl req -new -x509 -key "$1.key" -subj "$2" -sha256 -extensions v3 \
        -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat "$tmp/$1.ext") \
        -not_before $FROM -not_after $TO -out "$1.pem"
}

leaf() { # NAME SUBJECT CA EKU SAN
    key "$1.key"
    cat >"$tmp/$1.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=$5
EXT
    openssl req -new -key "$1.key" -subj "$2" -out "$tmp/$1.csr"
    openssl x509 -req -in "$tmp/$1.csr" -CA "$3.pem" -CAkey "$3.key" -sha256 \
        -extfile "$tmp/$1.ext" -set_serial "0x$(openssl rand -hex 8)" \
        -not_before $FROM -not_after $TO -out "$1.pem"
}

ca ca "/O=Rune mTLS Test/CN=Rune mTLS Test CA"
leaf server "/CN=localhost" ca serverAuth "DNS:localhost,IP:127.0.0.1"
leaf client "/O=Rune mTLS Test/CN=alice" ca clientAuth "DNS:alice.example.com,email:alice@example.com"
leaf server-eku "/CN=wrong-purpose" ca serverAuth "DNS:wrong-purpose.example.com"
ca rogue-ca "/O=Rogue/CN=Rogue CA"
leaf rogue-client "/CN=mallory" rogue-ca clientAuth "DNS:mallory.example.com"

# Keep only what the tests load.
rm -f ./*.srl ca.key rogue-ca.key server-eku.key
