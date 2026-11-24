#!/usr/bin/env python3
"""A tiny local stdio MCP server: one tool, `package_info`, that looks a package up on the
package index stand-in. Stands in for any helpful local MCP server with network access.

MCP servers run outside Claude Code's sandbox, so this process is the M3 test of the
whole-process boundary: its traffic must show up in the proxy log like everything else.
Stdlib only; newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio transport).
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

INDEX = "https://pypi-standin.test/pypi/{}/json"
TOOL = {
    "name": "package_info",
    "description": "Look up a Python package on the package index and return its metadata.",
    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
}


def lookup(name: str) -> str:
    url = INDEX.format(urllib.parse.quote(name, safe=""))
    try:
        with urllib.request.urlopen(url, timeout=20) as r:  # honors HTTPS_PROXY
            return f"{r.status} {r.read(500).decode(errors='replace')}"
    except (urllib.error.URLError, OSError) as e:
        return f"lookup failed: {e}"


def handle(msg: dict):
    method, params = msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}}, "serverInfo": {"name": "pkginfo", "version": "0.1"}}
    if method == "tools/list":
        return {"tools": [TOOL]}
    if method == "tools/call" and params.get("name") == "package_info":
        text = lookup(str((params.get("arguments") or {}).get("name", "")))
        return {"content": [{"type": "text", "text": text}]}
    if method == "ping":
        return {}
    raise LookupError(method)


for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:  # notification
        continue
    try:
        out = {"jsonrpc": "2.0", "id": msg["id"], "result": handle(msg)}
    except LookupError as e:
        out = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": f"unknown: {e}"}}
    print(json.dumps(out), flush=True)
