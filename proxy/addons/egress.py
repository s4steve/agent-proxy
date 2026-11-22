"""Egress logging addon: one JSON line per flow, no bodies.

M2 is observe-only: everything is allowed and logged. Policy, detectors and enforcement
arrive in M4 and plug into `decide()`.

Never logged: request/response bodies (any host); headers and query strings for
api.anthropic.com (the agent's own model traffic carries prompts and the login token).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from mitmproxy import http, tls

LOG_PATH = Path(os.environ.get("EGRESS_LOG", "/log/flows.jsonl"))
MODE = os.environ.get("POLICY_MODE", "observe")
# Hosts whose traffic is logged with host, method, bare path and timing only.
REDACTED_HOSTS = {"api.anthropic.com"}
# TLS hosts passed through without interception. Empty in M2: everything is inspected.
SPLICE_HOSTS: dict[str, str] = {}  # host -> reason


def _write(rec: dict) -> None:
    rec = {"time": round(time.time(), 3), **rec}
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def decide(flow: http.HTTPFlow) -> tuple[str | None, str]:
    """(rule matched, action). M2: no rules, everything allowed."""
    return None, "allow"


def flow_record(flow: http.HTTPFlow) -> dict:
    req = flow.request
    host = req.pretty_host
    redacted = host in REDACTED_HOSTS
    rule, action = decide(flow)
    rec: dict = {
        "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
        "process": None,  # not knowable from a sidecar proxy; see docs/DECISIONS.md
        "sni": flow.client_conn.sni,
        "host": host,
        "method": req.method,
        "path": urlsplit(req.path).path,
        "mode": MODE,
        "rule": rule,
        "action": action,
        "detector_hits": [],
    }
    if not redacted:
        rec["query_keys"] = sorted({k for k, _ in parse_qsl(urlsplit(req.path).query, keep_blank_values=True)})
        rec["user_agent"] = req.headers.get("user-agent")
        rec["req_bytes"] = len(req.raw_content or b"")
    if flow.response:
        rec["status"] = flow.response.status_code
        end = flow.response.timestamp_end or time.time()
        rec["latency_ms"] = round((end - req.timestamp_start) * 1000, 1)
    if flow.error:
        rec["error"] = flow.error.msg
    return rec


class Egress:
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

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Don't buffer the model's streamed (SSE) responses, or any other event stream.
        ctype = flow.response.headers.get("content-type", "") if flow.response else ""
        if flow.request.pretty_host in REDACTED_HOSTS or ctype.startswith("text/event-stream"):
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow) -> None:
        _write({"event": "flow", **flow_record(flow)})

    def error(self, flow: http.HTTPFlow) -> None:
        _write({"event": "flow", **flow_record(flow)})


addons = [Egress()]
