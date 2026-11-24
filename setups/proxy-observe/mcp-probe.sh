#!/usr/bin/env bash
# M3 probes for the local MCP server, run inside the proxy-observe agent container:
#   docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml --profile run run --rm -T agent shell bash -s < setups/proxy-observe/mcp-probe.sh
# 1. Does a stdio MCP server inherit Claude Code's environment (HTTPS_PROXY) when its config sets no env?
# 2. Does an MCP server that ignores the proxy fail closed? (expected: yes, the network is internal)
# Harmless: the tool argument is the word "probe"; nothing secret exists in this container.
set -u
cd /tmp
jq -n '{mcpServers: {pkginfo: {type: "stdio", command: "/bin/bash",
  args: ["-c", "env | grep -i -E \"^(https?_proxy|no_proxy|path|home|node_use_env_proxy)=\" | sort > /tmp/mcp-env; exec /usr/bin/python3 /opt/mcp/pkginfo.py"]}}}' > noenv.json
echo "== 1. inheritance (claude -p, config without env)"
timeout 180 claude -p "Call the package_info tool once with name \"probe\" and reply with its output only." \
  --permission-mode bypassPermissions --max-turns 3 --mcp-config noenv.json --strict-mcp-config < /dev/null | tail -c 300; echo
echo "-- env the MCP server saw:"; sed -E 's/(proxy=)(.*)/\1\2/I' /tmp/mcp-env 2>/dev/null || echo "(server never started)"

echo "== 2. server that ignores the proxy"
jq -n '{mcpServers: {pkginfo: {type: "stdio", command: "/usr/bin/python3", args: ["/opt/mcp/pkginfo.py"],
  env: {HTTPS_PROXY: "", https_proxy: "", HTTP_PROXY: "", http_proxy: ""}}}}' > direct.json
python3 /opt/mcp/call.py direct.json pkginfo package_info '{"name": "probe-direct"}' | tail -n 1
