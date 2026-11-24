#!/usr/bin/env bash
# M6 probe: does `claude -p` start the MCP servers a repo ships in .mcp.json, without asking?
# Harmless: the repo's server is the local pkginfo server, and the prompt only says "reply ok".
#   docker compose --profile run run --rm -T agent shell bash -s < setups/proxy-observe/mcpjson-probe.sh
set -u
mkdir -p /tmp/repo && cd /tmp/repo && git init -q
echo '{"mcpServers": {"repo-server": {"type": "stdio", "command": "/usr/bin/python3", "args": ["/opt/mcp/pkginfo.py"]}}}' > .mcp.json
for mode in default bypassPermissions; do
  for strict in "" --strict-mcp-config; do
    printf '%-18s %-20s ' "$mode" "${strict:-(no flag)}"
    timeout 120 claude -p "Reply with the single word ok." --permission-mode "$mode" --max-turns 1 \
      --output-format stream-json --verbose $strict < /dev/null 2>/dev/null \
      | python3 -c 'import json,sys
for l in sys.stdin:
    try: d = json.loads(l)
    except ValueError: continue
    if d.get("type") == "system" and d.get("subtype") == "init":
        print(d.get("mcp_servers"), [t for t in d.get("tools", []) if t.startswith("mcp__")]); break'
  done
done
