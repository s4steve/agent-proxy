"""Egress addon tests. Run inside the proxy image:
    docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml run --rm -T proxy python -m pytest -q /addons/tests
Uses mitmproxy's internal test helpers (tflow/taddons); their API isn't guaranteed stable.
"""

import json

import pytest
from mitmproxy.test import taddons, tflow

import egress


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = tmp_path / "flows.jsonl"
    monkeypatch.setattr(egress, "LOG_PATH", path)
    return path


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_flow(host, path="/", body=b"", headers=None):
    f = tflow.tflow(resp=True)
    f.request.host = host
    f.request.headers["host"] = host
    f.request.path = path
    f.request.content = body
    for k, v in (headers or {}).items():
        f.request.headers[k] = v
    return f


def test_logs_one_line_without_body_or_query_values(log):
    addon = egress.Egress()
    with taddons.context(addon):
        addon.response(make_flow("evil.test", "/r?fp=SECRETVALUE&x=1", body=b"BODYSECRET",
                                 headers={"user-agent": "curl/7.88.1"}))
    (rec,) = records(log)
    assert rec["host"] == "evil.test" and rec["path"] == "/r" and rec["action"] == "allow"
    assert rec["query_keys"] == ["fp", "x"] and rec["req_bytes"] == len(b"BODYSECRET")
    raw = log.read_text()
    assert "SECRETVALUE" not in raw and "BODYSECRET" not in raw


def test_anthropic_api_logs_no_headers_query_or_sizes(log):
    addon = egress.Egress()
    with taddons.context(addon):
        addon.response(make_flow("api.anthropic.com", "/v1/messages?beta=true", body=b"PROMPT",
                                 headers={"authorization": "Bearer TOKEN", "user-agent": "claude-cli"}))
    (rec,) = records(log)
    assert rec["path"] == "/v1/messages"
    assert not {"query_keys", "user_agent", "req_bytes"} & rec.keys()
    raw = log.read_text()
    assert "TOKEN" not in raw and "PROMPT" not in raw and "beta" not in raw


def test_model_responses_are_streamed_not_buffered(log):
    addon = egress.Egress()
    f = make_flow("api.anthropic.com")
    with taddons.context(addon):
        addon.responseheaders(f)
    assert f.response.stream is True


def basic(user):
    import base64
    return "Basic " + base64.b64encode(f"{user}:".encode()).decode()


def test_process_label_from_connect_applies_to_tunnelled_flows(log):
    addon = egress.Egress()
    with taddons.context(addon):
        connect = make_flow("pypi-standin.test", headers={"proxy-authorization": basic("mcp-pkginfo")})
        connect.request.method = "CONNECT"
        addon.http_connect(connect)
        inner = make_flow("pypi-standin.test", "/pypi/x/json")
        inner.client_conn = connect.client_conn
        addon.response(inner)
        addon.response(make_flow("evil.test"))  # another connection, no label
        addon.client_disconnected(connect.client_conn)
    assert [r["process"] for r in records(log)] == ["mcp-pkginfo", None]
    assert connect.client_conn.id not in egress.LABELS


def test_plain_http_label_is_logged_and_not_forwarded(log):
    addon = egress.Egress()
    with taddons.context(addon):
        f = make_flow("evil.test", headers={"proxy-authorization": basic("mcp-pkginfo")})
        addon.request(f)
        addon.response(f)
    assert records(log)[0]["process"] == "mcp-pkginfo"
    assert "proxy-authorization" not in f.request.headers
    assert egress.proxy_label({"proxy-authorization": "Basic !!notb64"}) is None
