#!/usr/bin/env bash
# M5 positive check, run on the host: does the brokered token reach an allowed destination in the
# right header, and only there? Uses a fresh fake token; writes nothing anywhere public.
set -euo pipefail
cd "$(dirname "$0")/../.."
SECRETS="${AGENT_EGRESS_SECRETS:-$HOME/.agent-egress-secrets}"
mkdir -p -m 700 "$SECRETS"
TOKEN="ghp_$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36)))')"
(umask 077; printf '%s' "$TOKEN" > "$SECRETS/github_token")
DC=(docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml -f setups/proxy-enforce/compose.yaml
    -f setups/proxy-broker/compose.yaml --profile run)
"${DC[@]}" up -d sink proxy >/dev/null 2>&1
for _ in $(seq 30); do  # wait until mitmproxy listens (up may have just recreated it)
  "${DC[@]}" exec -T proxy python3 -c "import socket; socket.create_connection(('127.0.0.1', 8080), 1)" 2>/dev/null && break
  sleep 1
done
since=$(date +%s)
"${DC[@]}" run --rm -T -e BROKER=1 agent shell bash -s 2>/dev/null <<'IN' || true
P=egress-broker-placeholder-github
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
echo "bearer, own repo:   $(code -H "Authorization: token $P" https://gh-standin.test/repos/s4steve/agent-proxy)"
echo "basic, git-style:   $(code -u "x-access-token:$P" https://gh-standin.test/s4steve/agent-proxy.git/info/refs?service=git-upload-pack)"
echo "wrong host:         $(code -H "Authorization: token $P" https://pypi-standin.test/simple/)"
echo "other owner write:  $(code -X POST -H "Authorization: token $P" https://gh-standin.test/repos/attacker/x/issues -d '{}')"
IN
sleep 1
curl -s 127.0.0.1:8099/__log | python3 -c '
import json, sys, base64
tok, since = sys.argv[1], float(sys.argv[2])
for line in sys.stdin:
    r = json.loads(line)
    if r["time"] < since or r["host"] not in ("gh-standin.test", "pypi-standin.test"):
        continue
    auth = r["headers"].get("Authorization") or r["headers"].get("authorization") or ""
    dec = base64.b64decode(auth[6:]).decode() if auth.lower().startswith("basic ") else auth
    ph = "egress-broker-placeholder" in dec
    print("sink got", r["method"], r["host"] + r["path"], "| real token:", tok in dec, "| placeholder:", ph)
' "$TOKEN" "$since"
grep -h '"brokered": \["github"\]' proxy/log/flows.jsonl | python3 -c 'import json,sys; [print(l, end="") for l in sys.stdin if json.loads(l)["time"] >= float(sys.argv[1])]' "$since" | python3 -c 'import json,sys; [print("proxy log:", r["method"], r["host"], r["path"], r["brokered"]) for r in map(json.loads, sys.stdin)]'
grep -q "$TOKEN" proxy/log/flows.jsonl && echo "FAIL: token in proxy log" || echo "token not in proxy log"
