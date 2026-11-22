#!/usr/bin/env bash
# Remove every trust anchor this project created. Nothing was ever added to the macOS keychain,
# so this only deletes the CA directory and the containers/volumes that copied certs in.
set -euo pipefail
cd "$(dirname "$0")/../.."
docker compose down --volumes --remove-orphans 2>/dev/null || true
docker image rm agent-egress-agent agent-egress-sink 2>/dev/null || true
rm -rf "${AGENT_EGRESS_CA_DIR:-$HOME/.agent-egress-ca}"
echo "removed CA dir, compose volumes and images"
