#!/usr/bin/env bash
# Proxy CA: an offline root plus an intermediate that mitmproxy uses to sign leaf certificates.
#   ~/.agent-egress-ca/root/    root key + cert. Never committed, never mounted into any container.
#   ~/.agent-egress-ca/proxy/   mitmproxy-ca.pem = intermediate key + intermediate cert (0600).
#                               Mounted into the proxy container only, as its confdir.
#   ~/.agent-egress-ca/public/  proxy-root.pem: the root cert, baked into the agent image as a trust anchor.
# Nothing is ever added to the macOS keychain. remove-trust.sh deletes all of it.
set -euo pipefail
BASE="${AGENT_EGRESS_CA_DIR:-$HOME/.agent-egress-ca}"
mkdir -p "$BASE/root" "$BASE/proxy" "$BASE/public" && chmod 700 "$BASE/root" "$BASE/proxy"

if [[ ! -f "$BASE/root/root.pem" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$BASE/root/root.key"
  chmod 600 "$BASE/root/root.key"
  openssl req -x509 -new -key "$BASE/root/root.key" -sha256 -days 1826 \
    -subj "/CN=agent-egress proxy root" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$BASE/root/root.pem"
fi

if [[ ! -f "$BASE/proxy/mitmproxy-ca.pem" ]]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$tmp/int.key"
  openssl req -new -key "$tmp/int.key" -subj "/CN=agent-egress proxy intermediate" -out "$tmp/int.csr"
  openssl x509 -req -in "$tmp/int.csr" -CA "$BASE/root/root.pem" -CAkey "$BASE/root/root.key" \
    -CAcreateserial -sha256 -days 365 \
    -extfile <(printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" \
      "keyUsage=critical,keyCertSign,cRLSign" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid") \
    -out "$tmp/int.pem"
  # mitmproxy reads key + certs from one file; the first cert signs leaves. With a single cert
  # mitmproxy 12.3.1 serves the leaf alone and clients can't build a path to the root (tested,
  # docs/DECISIONS.md M2). With more than one cert it serves all of them as the chain, so append
  # the root *certificate*. The root key never leaves ~/.agent-egress-ca/root/.
  (umask 077; cat "$tmp/int.key" "$tmp/int.pem" "$BASE/root/root.pem" > "$BASE/proxy/mitmproxy-ca.pem")
fi

cp "$BASE/root/root.pem" "$BASE/public/proxy-root.pem"
openssl verify -CAfile "$BASE/root/root.pem" <(openssl x509 -in "$BASE/proxy/mitmproxy-ca.pem")
echo "proxy CA ready: root in $BASE/root (offline), intermediate in $BASE/proxy"
