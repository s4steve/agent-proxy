"""Egress addon: decides every request against policy.yaml and logs one JSON line per flow.

POLICY_MODE=observe logs what the policy would do and blocks nothing (M2's setup);
POLICY_MODE=enforce answers denied requests with a 403 from the proxy (M4).

Never logged: request/response bodies (any host); headers and query strings for
api.anthropic.com (the agent's own model traffic carries prompts and the login token).
Paths are logged with secret-shaped and high-entropy segments redacted.
Brokered credentials (M5) are logged by name only; the secret never reaches the log or the agent.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http, tcp, tls

sys.path.insert(0, os.path.dirname(__file__))
import policy  # noqa: E402

LOG_PATH = Path(os.environ.get("EGRESS_LOG", "/log/flows.jsonl"))
POLICY_PATH = os.environ.get("POLICY_FILE", "/policy/policy.yaml")
MODE = os.environ.get("POLICY_MODE", "observe")
# Hosts whose traffic is logged with host, method, bare path and timing only.
REDACTED_HOSTS = {"api.anthropic.com"}
# TLS hosts passed through without interception. Empty: everything is inspected.
SPLICE_HOSTS: dict[str, str] = {}  # host -> reason
# Client connection id -> process label from the CONNECT's Proxy-Authorization username (M3).
LABELS: dict[str, str] = {}
# Transparent mode (setups/proxy-dns): client connection id -> (name, port) to connect to.
TARGETS: dict[str, tuple[str, int]] = {}
_policy_file: policy.PolicyFile | None = None
_reported_error: str | None = None


def _write(rec: dict) -> None:
    rec = {"time": round(time.time(), 3), **rec}
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def current_policy() -> policy.Policy:
    global _policy_file, _reported_error
    if _policy_file is None:
        _policy_file = policy.PolicyFile(POLICY_PATH)
    p = _policy_file.get()
    if _policy_file.error != _reported_error:
        _reported_error = _policy_file.error
        _write({"event": "policy_reload_failed" if _reported_error else "policy_reloaded",
                "error": _reported_error, "checks": sorted(p.checks)})
    return p


def proxy_label(headers) -> str | None:
    """Username from a Basic Proxy-Authorization header: a self-reported process label.

    A client sets it by putting a username in its proxy URL (http://mcp-pkginfo:label@proxy:8080).
    It attributes traffic; it proves nothing, since any process can claim any label.
    """
    v = headers.get("proxy-authorization", "")
    if not v.lower().startswith("basic "):
        return None
    try:
        return base64.b64decode(v[6:]).decode().split(":", 1)[0] or None
    except ValueError:
        return None


def transparent(flow: http.HTTPFlow) -> bool:
    return getattr(flow.client_conn.proxy_mode, "type_name", "") == "transparent"


def dest_of(flow: http.HTTPFlow) -> str:
    """Where the bytes go: the CONNECT target for tunnelled requests; in transparent mode the
    TLS SNI (or Host for plain HTTP); else the request host."""
    if transparent(flow):
        return flow.client_conn.sni or (flow.request.host_header or "").rsplit(":", 1)[0]
    addr = flow.server_conn.address
    return addr[0] if addr else flow.request.host


def to_request(flow: http.HTTPFlow) -> policy.Request:
    req = flow.request
    return policy.Request(method=req.method, dest=dest_of(flow), host=req.pretty_host,
                          sni=flow.client_conn.sni, path=req.path, headers=list(req.headers.items()),
                          body=req.get_content(strict=False) or b"")


def flow_record(flow: http.HTTPFlow) -> dict:
    req = flow.request
    host = req.pretty_host
    rule, decision, reason, hits = flow.metadata.get("decision", (None, None, "", []))
    rec: dict = {
        "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
        # Not knowable from a sidecar proxy, except by a self-reported label; see docs/DECISIONS.md.
        "process": flow.metadata.get("process") or LABELS.get(flow.client_conn.id),
        "sni": flow.client_conn.sni,
        "host": host,
        "method": req.method,
        "path": policy.redact_path(req.path),
        "mode": MODE,
        "rule": rule,
        "decision": decision,
        "reason": reason,
        "action": "block" if flow.metadata.get("blocked") else "allow",
        "detector_hits": hits,
        "brokered": flow.metadata.get("brokered", []),
        "mcp_tools": [t for _, t in policy.mcp_calls(req.get_content(strict=False) or b"")]
        if req.method == "POST" and flow.metadata.get("mcp_tools") is not None else None,
    }
    if (dest := dest_of(flow)) != host:
        rec["dest"] = dest
    if host not in REDACTED_HOSTS:
        rec["query_keys"] = sorted({kv.partition("=")[0] for kv in urlsplit(req.path).query.split("&") if kv})
        rec["user_agent"] = req.headers.get("user-agent")
        rec["req_bytes"] = len(req.raw_content or b"")
    if flow.response:
        rec["status"] = flow.response.status_code
        end = flow.response.timestamp_end or time.time()
        rec["latency_ms"] = round((end - req.timestamp_start) * 1000, 1)
    if flow.error:
        rec["error"] = flow.error.msg
    return rec


def block(flow: http.HTTPFlow, reason: str) -> None:
    flow.metadata["blocked"] = True
    msg = f"blocked by agent egress policy: {reason}"
    calls = policy.mcp_calls(flow.request.get_content(strict=False) or b"") if flow.request.method == "POST" else []
    if calls:  # an MCP tools/call: answer in JSON-RPC so the client reports a tool error, not a dead server
        body = json.dumps({"jsonrpc": "2.0", "id": calls[0][0], "error": {"code": -32001, "message": msg}})
        flow.response = http.Response.make(200, body, {"content-type": "application/json"})
    else:
        flow.response = http.Response.make(403, msg + "\n", {"content-type": "text/plain"})


class Egress:
    def http_connect(self, flow: http.HTTPFlow) -> None:
        if label := proxy_label(flow.request.headers):
            LABELS[flow.client_conn.id] = label
        # Refuse tunnels to destinations no rule covers, so non-HTTP traffic can't use them either.
        if MODE == "enforce" and current_policy().rule_for(flow.request.host) is None:
            flow.metadata["decision"] = (None, "deny", "no rule for destination", [])
            block(flow, "no rule for destination")
            _write({"event": "flow", **flow_record(flow)})

    def client_disconnected(self, client) -> None:
        LABELS.pop(client.id, None)
        TARGETS.pop(client.id, None)

    def server_connect(self, data) -> None:
        # Transparent mode: the client dialled the proxy's own address (that's what DNS told it).
        # Connect to the name the policy judged, never to an address the client chose.
        if (target := TARGETS.get(data.client.id)) is not None:
            data.server.address = target

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        sni = data.client_hello.sni
        if sni in SPLICE_HOSTS:
            data.ignore_connection = True
            _write({"event": "splice", "sni": sni, "reason": SPLICE_HOSTS[sni]})

    def tls_failed_client(self, data: tls.TlsData) -> None:
        # The client rejected our certificate (pinning, or it ignores the CA settings).
        # This is how tools that ignore SSL_CERT_FILE etc. show up.
        _write({"event": "tls_failed_client", "sni": data.conn.sni,
                "client": data.conn.peername[0] if data.conn.peername else None,
                "error": data.conn.error})

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        # Non-HTTP inside an allowed tunnel (e.g. ssh over CONNECT): no rules cover it.
        _write({"event": "tcp", "dest": flow.server_conn.address[0] if flow.server_conn.address else None,
                "action": "block" if MODE == "enforce" else "allow"})
        if MODE == "enforce":
            flow.kill()

    def request(self, flow: http.HTTPFlow) -> None:
        # Plain-HTTP proxy requests carry the label themselves. Never forward it upstream.
        if label := proxy_label(flow.request.headers):
            flow.metadata["process"] = label
        flow.request.headers.pop("proxy-authorization", None)
        if transparent(flow):
            name = dest_of(flow)
            if not name:
                flow.metadata["decision"] = (None, "deny", "no SNI or Host", [])
                block(flow, "no SNI or Host")
                return
            TARGETS[flow.client_conn.id] = (name, flow.request.port)
        pol = current_policy()
        rule, decision, reason, hits = policy.decide(pol, to_request(flow))
        flow.metadata["decision"] = (rule, decision, reason, hits)
        matched = pol.rule_for(dest_of(flow), flow.request.path)
        # Filtering tools/list changes what the agent sees, so it's enforce-only like blocking.
        if matched and matched.mcp_tools is not None and "mcp" in pol.checks and MODE == "enforce":
            flow.metadata["mcp_tools"] = matched.mcp_tools
        if decision == "deny":
            if MODE == "enforce":
                block(flow, reason)
            return  # observe mode passes it through, but never with a real secret
        # Transparent mode: aim the request at the name just judged, so mitmproxy connects there
        # and can reuse that upstream connection (it matches connections by request host).
        # (Setting host also rewrites the Host header; a request whose Host differed from its SNI
        # was already denied by sni_host, or, with that check off, is now sent to the SNI's host.)
        if transparent(flow) and flow.request.host != (name := dest_of(flow)):
            flow.request.host = name
        # Credential broker (M5): only allowed requests get the real secret, only in its headers.
        headers, used = policy.inject(pol, to_request(flow))
        if used:
            flow.request.headers = http.Headers([(k.encode(), v.encode()) for k, v in headers])
            flow.metadata["brokered"] = used
            flow.metadata["scrub"] = [(c.secret(), c.placeholder) for c in pol.credentials if c.name in used]

    def _scrub(self, flow: http.HTTPFlow) -> None:
        """Replace an echoed secret with its placeholder, so the agent never reads it back."""
        resp = flow.response
        for secret, placeholder in flow.metadata.get("scrub", []):
            if not secret:
                continue
            for k, v in list(resp.headers.items()):
                if secret in v:
                    resp.headers[k] = v.replace(secret, placeholder)
            if not resp.stream and resp.content and secret.encode() in resp.content:
                resp.content = resp.content.replace(secret.encode(), placeholder.encode())

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Don't buffer the model's streamed (SSE) responses, or any other event stream.
        ctype = flow.response.headers.get("content-type", "") if flow.response else ""
        if flow.request.pretty_host in REDACTED_HOSTS or ctype.startswith("text/event-stream"):
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow) -> None:
        self._scrub(flow)
        allowed = flow.metadata.get("mcp_tools")
        if allowed is not None and not flow.response.stream and \
                flow.response.headers.get("content-type", "").startswith("application/json"):
            if (new := policy.filter_tools_list(flow.response.content or b"", allowed)) is not None:
                flow.response.content = new
                flow.metadata["mcp_filtered"] = True
        _write({"event": "flow", **flow_record(flow)})

    def error(self, flow: http.HTTPFlow) -> None:
        _write({"event": "flow", **flow_record(flow)})


addons = [Egress()]
