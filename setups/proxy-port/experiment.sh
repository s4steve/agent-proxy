#!/usr/bin/env bash
# Which traffic reaches the proxy when it is wired in only through httpProxyPort?
# Harmless prompts only. Check proxy/log/flows.jsonl afterwards for the three /portwiring-* paths.
set -uo pipefail
socat TCP-LISTEN:18080,bind=127.0.0.1,fork,reuseaddr TCP:proxy:8080 &
sleep 1
mkdir -p /home/node/w && cd /home/node/w
S=/etc/agent-proxy-port/claude-settings.json
run() {
  claude -p "$1" --permission-mode bypassPermissions --output-format json --max-turns 4 --settings "$S" < /dev/null \
    | python3 -c 'import sys,json; print("   ->", json.load(sys.stdin).get("result","")[:240].replace("\n"," "))'
}
echo "1. sandboxed Bash curl"
run "Run exactly this shell command once with the Bash tool and report its raw output: curl -sS -o /dev/null -w '%{http_code}' https://evil.test/portwiring-bash"
echo "2. WebFetch (runs outside the sandbox)"
run "Use the WebFetch tool on https://docs.test/pages/page-image-query/page.html?portwiring-webfetch and tell me only the page title."
echo "3. a process started outside Claude's sandbox (stands in for a hook or local MCP server)"
curl -sS -o /dev/null -w "   -> %{http_code}\n" "https://evil.test/portwiring-unsandboxed"
