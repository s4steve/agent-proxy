"""Egress addon tests. Run inside the proxy image:
    docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml run --rm -T proxy python -m pytest -q /addons/tests
Uses mitmproxy's internal test helpers (tflow/taddons); their API isn't guaranteed stable.
"""

import json

import pytest
from mitmproxy.test import taddons, tflow

import egress


POLICY = """
checks: [actions, github, sni_host, secrets, entropy]
rules:
  - {name: github, hosts: [gh-standin.test], github_owners: [me], allow_auth_header: true}
  - {name: pkgs, hosts: [pypi-standin.test], methods: [GET, HEAD]}
"""


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = tmp_path / "flows.jsonl"
    pol = tmp_path / "policy.yaml"
    pol.write_text(POLICY)
    monkeypatch.setattr(egress, "LOG_PATH", path)
    monkeypatch.setattr(egress, "POLICY_PATH", str(pol))
    monkeypatch.setattr(egress, "_policy_file", None)
    monkeypatch.setattr(egress, "MODE", "enforce")
    monkeypatch.delenv("POLICY_CHECKS", raising=False)
    return path


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def make_flow(host, path="/", body=b"", headers=None):
    f = tflow.tflow(resp=True)
    f.request.host = host
    f.server_conn.address = (host, 443)
    f.client_conn.sni = host
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


def test_enforce_blocks_with_403_and_logs_reason_without_the_secret(log):
    addon = egress.Egress()
    token = "ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3"
    with taddons.context(addon):
        f = make_flow("pypi-standin.test", f"/pypi/slugify-{token}/json")
        addon.request(f)
        addon.response(f)
        ok = make_flow("pypi-standin.test", "/simple/requests/")
        addon.request(ok)
    assert f.response.status_code == 403 and ok.response.status_code == 200  # tflow's canned response
    (rec,) = records(log)
    assert rec["action"] == "block" and rec["decision"] == "deny" and rec["detector_hits"] == ["github_token"]
    assert rec["path"] == "/pypi/<redacted>/json" and token not in log.read_text()


def test_enforce_refuses_tunnels_to_unlisted_destinations(log):
    addon = egress.Egress()
    with taddons.context(addon):
        c = make_flow("evil.test")
        c.request.method = "CONNECT"
        addon.http_connect(c)
        c2 = make_flow("gh-standin.test")
        c2.request.method = "CONNECT"
        c2.response = None
        addon.http_connect(c2)
    assert c.response.status_code == 403 and c2.response is None
    assert records(log)[0]["reason"] == "no rule for destination"


def test_fronted_request_is_judged_by_destination_and_flagged(log):
    addon = egress.Egress()
    with taddons.context(addon):
        f = make_flow("gh-standin.test", "/upload")  # tunnel to an allowed host...
        f.request.headers["host"] = "evil.test"     # ...whose Host header names another
        addon.request(f)
        addon.response(f)
    rec = records(log)[0]
    assert rec["rule"] == "github" and rec["dest"] == "gh-standin.test" and rec["host"] == "evil.test"
    assert rec["action"] == "block" and "sni_host" in rec["detector_hits"]


def test_observe_mode_logs_the_decision_but_blocks_nothing(log, monkeypatch):
    monkeypatch.setattr(egress, "MODE", "observe")
    addon = egress.Egress()
    with taddons.context(addon):
        f = make_flow("gh-standin.test", "/gists", body=b"{}")
        f.request.method = "POST"
        addon.request(f)
        addon.response(f)
    rec = records(log)[0]
    assert rec["decision"] == "deny" and rec["action"] == "allow" and f.response.status_code == 200


def test_broker_injects_upstream_scrubs_the_echo_and_logs_only_the_name(log, tmp_path, monkeypatch):
    secret = tmp_path / "github_token"
    secret.write_text("REALSECRET123\n")
    pol = tmp_path / "policy.yaml"
    pol.write_text(POLICY + f"""credentials:
  - {{name: github, placeholder: PH-github, secret_file: {secret}, hosts: [gh-standin.test]}}
""")
    addon = egress.Egress()
    with taddons.context(addon):
        f = make_flow("gh-standin.test", "/repos/me/x", headers={"authorization": "token PH-github"})
        addon.request(f)
        assert f.request.headers["authorization"] == "token REALSECRET123"
        f.response.content = b"you sent REALSECRET123"
        f.response.headers["x-echo"] = "REALSECRET123"
        addon.response(f)
        bad = make_flow("pypi-standin.test", "/simple/", headers={"authorization": "token PH-github"})
        addon.request(bad)
    assert f.response.content == b"you sent PH-github" and f.response.headers["x-echo"] == "PH-github"
    assert bad.response.status_code == 403 and bad.request.headers["authorization"] == "token PH-github"
    assert records(log)[0]["brokered"] == ["github"] and "REALSECRET123" not in log.read_text()


def test_observe_mode_never_injects_into_a_denied_request(log, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "MODE", "observe")
    secret = tmp_path / "github_token"
    secret.write_text("REALSECRET123")
    (tmp_path / "policy.yaml").write_text(POLICY + f"""credentials:
  - {{name: github, placeholder: PH-github, secret_file: {secret}, hosts: [gh-standin.test]}}
""")
    addon = egress.Egress()
    with taddons.context(addon):
        f = make_flow("gh-standin.test", "/gists", headers={"authorization": "token PH-github"})
        f.request.method = "POST"
        addon.request(f)
    assert f.request.headers["authorization"] == "token PH-github"
