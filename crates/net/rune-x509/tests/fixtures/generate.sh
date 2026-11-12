#!/usr/bin/env bash
# Regenerates the test certificates in this directory with OpenSSL >= 3.4
# (for `-not_before` / `-not_after`). Keys are throwaway and deleted at the
# end, so a run produces a fresh set; tests rely only on the properties
# below, not on exact bytes. Run from anywhere: `bash tests/fixtures/generate.sh`.
#
# Layout (validity in brackets; tests evaluate at 2026-06-01T00:00:00Z):
#   root.pem          RSA-2048 root CA, sha256           [2025 .. 2035]
#   other-root.pem    EC P-256 root CA not put in the store [2025 .. 2035]
#   inter.pem         EC P-256 intermediate, pathlen:0, by root [2025 .. 2035]
#   leaf.pem          EC P-256 leaf by inter: example.com, www.example.com,
#                     192.0.2.1, one embedded SCT     [2026-01-01 .. 2027-01-01]
#   wildcard.pem      EC P-256 leaf by inter: *.example.com
#   expired.pem       EC P-256 leaf by inter: expired.example.com [2020 .. 2021]
#   sha1.pem          RSA-2048 leaf by root, sha1WithRSAEncryption: sha1.example.com
#   self-signed.pem   RSA-2048 self-signed leaf: self.example.com
#   untrusted.pem     EC P-256 leaf by other-root: untrusted.example.com
#   weak-rsa.pem      RSA-1024 self-signed, sha256: weak.example.com
#   ed25519.pem       Ed25519 self-signed CA: ed25519.example.com
#   notca-leaf.pem    EC P-256 leaf signed by leaf.pem's key (leaf is not a CA)
#   cn-only.pem       EC P-256 self-signed, no SAN: CN=cn-only.example.com
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

CA_FROM=20250101000000Z
CA_TO=20350101000000Z
LEAF_FROM=20260101000000Z
LEAF_TO=20270101000000Z

key_rsa() { openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$1" 2>/dev/null; }
key_ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# An SCT list with one structurally valid (but unsigned) SCT, as the DER
# OCTET STRING that is the extension value.
SCT="DER:0437003500330011111111111111111111111111111111111111111111111111111111111111110000019400000000000004030004deadbeef"

ca_ext() {
    cat >"$tmp/$1.ext" <<EXT
basicConstraints=critical,CA:TRUE$2
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EXT
}
leaf_ext() {
    cat >"$tmp/$1.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=$2
EXT
}

# self_signed NAME KEY SUBJECT DIGEST EXTFILE FROM TO
self_signed() {
    openssl req -new -x509 -key "$2" -subj "$3" ${4:+-$4} -extensions v3 \
        -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat "$5") \
        -not_before "$6" -not_after "$7" -out "$1.pem"
}
# issue NAME KEY SUBJECT ISSUER_CERT ISSUER_KEY DIGEST EXTFILE FROM TO
issue() {
    openssl req -new -key "$2" -subj "$3" -out "$tmp/$1.csr"
    openssl x509 -req -in "$tmp/$1.csr" -CA "$4" -CAkey "$5" ${6:+-$6} \
        -extfile "$7" -set_serial "0x$(openssl rand -hex 8)" \
        -not_before "$8" -not_after "$9" -out "$1.pem"
}

key_rsa root.key 2048
ca_ext root ""
self_signed root root.key "/O=Rune Test/CN=Rune Test Root" sha256 "$tmp/root.ext" $CA_FROM $CA_TO

key_ec other-root.key
ca_ext other-root ""
self_signed other-root other-root.key "/O=Rune Other/CN=Rune Other Root" sha256 "$tmp/other-root.ext" $CA_FROM $CA_TO

key_ec inter.key
ca_ext inter ",pathlen:0"
echo "authorityKeyIdentifier=keyid" >>"$tmp/inter.ext"
issue inter inter.key "/O=Rune Test/CN=Rune Test Intermediate" root.pem root.key sha256 "$tmp/inter.ext" $CA_FROM $CA_TO

key_ec leaf.key
leaf_ext leaf "DNS:example.com,DNS:www.example.com,IP:192.0.2.1"
echo "1.3.6.1.4.1.11129.2.4.2=$SCT" >>"$tmp/leaf.ext"
issue leaf leaf.key "/CN=example.com" inter.pem inter.key sha256 "$tmp/leaf.ext" $LEAF_FROM $LEAF_TO

key_ec wildcard.key
leaf_ext wildcard "DNS:*.example.com"
issue wildcard wildcard.key "/CN=*.example.com" inter.pem inter.key sha256 "$tmp/wildcard.ext" $LEAF_FROM $LEAF_TO

key_ec expired.key
leaf_ext expired "DNS:expired.example.com"
issue expired expired.key "/CN=expired.example.com" inter.pem inter.key sha256 "$tmp/expired.ext" 20200101000000Z 20210101000000Z

key_rsa sha1.key 2048
leaf_ext sha1 "DNS:sha1.example.com"
issue sha1 sha1.key "/CN=sha1.example.com" root.pem root.key sha1 "$tmp/sha1.ext" $LEAF_FROM $LEAF_TO

key_rsa self-signed.key 2048
cat >"$tmp/self.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
subjectAltName=DNS:self.example.com
EXT
self_signed self-signed self-signed.key "/CN=self.example.com" sha256 "$tmp/self.ext" $LEAF_FROM $LEAF_TO

key_ec untrusted.key
leaf_ext untrusted "DNS:untrusted.example.com"
issue untrusted untrusted.key "/CN=untrusted.example.com" other-root.pem other-root.key sha256 "$tmp/untrusted.ext" $LEAF_FROM $LEAF_TO

key_rsa weak-rsa.key 1024
cat >"$tmp/weak.ext" <<EXT
subjectAltName=DNS:weak.example.com
EXT
self_signed weak-rsa weak-rsa.key "/CN=weak.example.com" sha256 "$tmp/weak.ext" $LEAF_FROM $LEAF_TO

openssl genpkey -algorithm ED25519 -out ed25519.key
ca_ext ed25519 ""
echo "subjectAltName=DNS:ed25519.example.com" >>"$tmp/ed25519.ext"
self_signed ed25519 ed25519.key "/CN=ed25519.example.com" "" "$tmp/ed25519.ext" $CA_FROM $CA_TO

key_ec notca-leaf.key
leaf_ext notca-leaf "DNS:notca.example.com"
issue notca-leaf notca-leaf.key "/CN=notca.example.com" leaf.pem leaf.key sha256 "$tmp/notca-leaf.ext" $LEAF_FROM $LEAF_TO

key_ec cn-only.key
cat >"$tmp/cn-only.ext" <<EXT
basicConstraints=critical,CA:FALSE
EXT
self_signed cn-only cn-only.key "/CN=cn-only.example.com" sha256 "$tmp/cn-only.ext" $LEAF_FROM $LEAF_TO

rm -f ./*.srl ./*.key
