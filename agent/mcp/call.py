#!/usr/bin/env python3
"""Replay client: call one tool on a server from an MCP config, the way Claude Code would.

Usage: call.py <config.json> <server> <tool> <json-arguments>
Spawns the server with the config's command, args and env (added to this environment),
does the initialize handshake, makes one tools/call and prints the result.
"""
import json
import os
import subprocess
import sys

cfg_path, server, tool, args = sys.argv[1:5]
s = json.load(open(cfg_path))["mcpServers"][server]
msgs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "replay", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": json.loads(args)}},
]
out = subprocess.run([s["command"], *s.get("args", [])], env={**os.environ, **s.get("env", {})},
                     input="".join(json.dumps(m) + "\n" for m in msgs), capture_output=True, text=True, timeout=60)
print(out.stdout, end="")
print(out.stderr, end="", file=sys.stderr)
