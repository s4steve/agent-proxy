#!/usr/bin/env bash
# Test CA for the sink (the "attacker" server). Separate from the proxy CA (M2).
# The CA key never leaves ~/.agent-egress-ca/sink/. Only ca.pem (public) and the
# sink leaf cert/key are mounted into containers.
set -euo pipefail
DIR="${AGENT_EGRESS_CA_DIR:-$HOME/.agent-egress-ca}/sink"
HOSTS=(sink docs.test evil.test collector.test gh-standin.test pypi-standin.test)

mkdir -p "$DIR" && chmod 700 "$DIR"
cd "$DIR"
if [[ -f ca.pem ]]; then mkdir -p ../public && cp ca.pem ../public/sink-ca.pem; echo "exists: $DIR/ca.pem (run remove-trust.sh to start over)"; exit 0; fi

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=agent-egress sink test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

SAN=$(printf 'DNS:%s,' "${HOSTS[@]}"); SAN=${SAN%,}
openssl ecparam -name prime256v1 -genkey -noout -out sink.key
openssl req -new -key sink.key -subj "/CN=sink" -out sink.csr
openssl x509 -req -in sink.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 90 \
  -extfile <(printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$SAN") \
  -out sink.pem
rm sink.csr
chmod 600 ca.key sink.key; chmod 644 ca.pem sink.pem
openssl verify -CAfile ca.pem sink.pem
# Public certs only: this dir is the agent image's build context, so no key is ever sent to the builder.
mkdir -p ../public && cp ca.pem ../public/sink-ca.pem
echo "sink CA ready in $DIR"
