"""Rule and detector tests: pure functions, no network. GitHub rules are covered here, never live."""

import base64
import os

import pytest

import policy as P

GH_OWNERS = ["s4steve"]
TOKEN = "ghp_" + "Zx9Qw8Er7Ty6" * 3
ENV = f"AWS_ACCESS_KEY_ID=AKIA{'ABCD2345EFGH6789'}\nGITHUB_TOKEN={TOKEN}\n"


@pytest.mark.parametrize("method,path,ok", [
    ("GET", "/torvalds/linux", True),                                          # browse anywhere
    ("GET", "/octocat/Hello-World/info/refs?service=git-upload-pack", True),   # clone: ref discovery
    ("POST", "/octocat/Hello-World/git-upload-pack", True),                    # clone: a POST that reads
    ("GET", "/attacker/drop.git/info/refs?service=git-receive-pack", False),   # push discovery, other owner
    ("POST", "/attacker/drop.git/git-receive-pack", False),                    # push to another owner
    ("POST", "/s4steve/agent-proxy.git/git-receive-pack", True),               # push to own repo
    ("POST", "/S4Steve/agent-proxy.git/git-receive-pack", True),               # owners are case-insensitive
    ("POST", "/repos/upstream-org/slugify/issues", False),                     # issue on someone else's repo
    ("PATCH", "/repos/s4steve/agent-proxy/issues/1", True),                    # API write to own repo
    ("POST", "/gists", False),                                                 # gists belong to no repo
    ("POST", "/user/repos", False),                                            # creating repos: not an owned repo path
    ("POST", "/graphql", False),                                               # known false positive: gh uses GraphQL
])
def test_github_rules(method, path, ok):
    assert P.github_allows(method, path, GH_OWNERS)[0] is ok


def req(dest, path="/", method="GET", host=None, sni=None, headers=(), body=b""):
    return P.Request(method, dest, host or dest, sni or dest, path, list(headers), body)


@pytest.mark.parametrize("r,hit", [
    (req("pypi-standin.test", f"/pypi/slugify-{TOKEN}/json"), "github_token"),          # MCP tool arg
    (req("evil.test", "/badge.svg?id=AKIAABCD2345EFGH6789&sig=x"), "aws_access_key"),    # query
    (req("evil.test", "/r?fp=" + base64.b64encode(ENV.encode()).decode()), "github_token"),  # base64 .env
    (req("collector.test", headers=[("x-api-key", "sk_live_" + "a1" * 12)]), "stripe_key"),  # header
    (req("pypi-standin.test", "/simple/",
         headers=[("authorization", "Basic " + base64.b64encode(f"__token__:{TOKEN}".encode()).decode())]),
     "github_token"),                                                                  # pip index Basic auth
    (req("gh-standin.test", "/gists", "POST", body=ENV.encode()), "aws_access_key"),     # body
    (req("gh-standin.test", "/upload", "POST", host="evil.test"), "sni_host"),           # fronting
    (req("evil.test", "/x", sni="gh-standin.test"), "sni_host"),
    (req("evil.test", "/r?d=" + base64.urlsafe_b64encode(os.urandom(30)).decode()), "entropy"),
])
def test_detectors_fire(r, hit):
    assert hit in P.detect(r, None)


@pytest.mark.parametrize("dest,path", [
    ("files.pythonhosted.org", "/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54"
                               "/requests-2.32.3-py3-none-any.whl"),
    # These wheels tripped the first entropy rule in the enforce work session (false positives).
    ("files.pythonhosted.org", "/packages/45/16/fcd396b14758f491a8dcb6c8/"
                               "charset_normalizer-3.4.2-cp311-cp311-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"),
    ("files.pythonhosted.org", "/packages/28/ec/cda85baa366071c48593774e/"
                               "charset_normalizer-3.3.2-cp311-cp311-musllinux_1_1_aarch64.whl"),
    ("files.pythonhosted.org", "/packages/4c/92/97509850f0d00e9f14a46bc7/cryptography-44.0.0-cp39-abi3-manylinux_2_28_aarch64.whl"),
    ("pypi.org", "/simple/requests/"),
    ("registry.npmjs.org", "/left-pad/-/left-pad-1.3.0.tgz"),
    ("github.com", "/octocat/Hello-World/info/refs?service=git-upload-pack"),
    ("codeload.github.com", "/octocat/Hello-World/tar.gz/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"),
    ("docs.python.org", "/3/library/urllib.request.html"),
    ("api.github.com", "/repos/octocat/Hello-World/commits?per_page=1&sha=7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"),
])
def test_ordinary_urls_trip_nothing(dest, path):
    assert P.detect(req(dest, path), None) == []


def test_github_token_to_github_is_allowed_but_not_elsewhere():
    gh = P.Rule("github", ["github.com"], allow_auth_header=True)
    auth = [("authorization", f"token {TOKEN}")]
    assert P.detect(req("github.com", headers=auth), gh) == []
    assert P.detect(req("pypi.org", headers=auth), P.Rule("pypi", ["pypi.org"])) == ["github_token"]


def test_uninspected_rule_is_not_scanned():
    assert P.detect(req("api.anthropic.com", body=ENV.encode()), P.Rule("a", ["api.anthropic.com"], inspect=False)) == []


POLICY = """
checks: [actions, github, sni_host, secrets, entropy]
rules:
  - {name: github, hosts: [gh-standin.test], github_owners: [me]}
  - {name: pkgs, hosts: [pypi-standin.test, "*.pkgs.test"], methods: [GET]}
"""


@pytest.mark.parametrize("checks,r,decision", [
    ("none", req("evil.test"), "deny"),                                          # host allowlist is always on
    ("none", req("a.pkgs.test"), "allow"),                                       # wildcard
    ("none", req("pypi-standin.test", method="POST"), "allow"),
    ("actions", req("pypi-standin.test", method="POST"), "deny"),
    ("actions", req("gh-standin.test", "/gists", "POST"), "allow"),
    ("actions,github", req("gh-standin.test", "/gists", "POST"), "deny"),
    ("github", req("gh-standin.test", "/u", "POST", host="evil.test"), "deny"),   # github rule denies this write
    ("none", req("gh-standin.test", "/u", host="evil.test"), "allow"),
    ("sni_host", req("gh-standin.test", "/u", host="evil.test"), "deny"),
    ("github", req("pypi-standin.test", f"/pypi/{TOKEN}/json"), "allow"),
    ("secrets", req("pypi-standin.test", f"/pypi/{TOKEN}/json"), "deny"),
])
def test_checks_turn_on_one_at_a_time(monkeypatch, checks, r, decision):
    monkeypatch.setenv("POLICY_CHECKS", checks)
    assert P.decide(P.parse(POLICY), r)[1] == decision


def test_unknown_check_is_an_error(monkeypatch):
    monkeypatch.setenv("POLICY_CHECKS", "secrets,typo")
    with pytest.raises(ValueError):
        P.parse(POLICY)


def test_hot_reload_and_bad_edit_keeps_last_good_policy(tmp_path, monkeypatch):
    monkeypatch.delenv("POLICY_CHECKS", raising=False)
    f = tmp_path / "p.yaml"
    f.write_text(POLICY)
    pf = P.PolicyFile(f)
    assert pf.get().rule_for("gh-standin.test")
    f.write_text("rules:\n  - {name: x, hosts: [only.test]}\n")
    os.utime(f, (1, 1))
    assert pf.get().rule_for("only.test") and not pf.get().rule_for("gh-standin.test")
    f.write_text("rules: [ {name: broken")
    os.utime(f, (2, 2))
    assert pf.get().rule_for("only.test") and pf.error


def test_redact_path():
    assert P.redact_path(f"/v1/license/{TOKEN}?q=1") == "/v1/license/<redacted>"
    assert P.redact_path("/simple/requests/") == "/simple/requests/"


def test_real_policy_file_parses():
    path = "/policy/policy.yaml"
    if not os.path.exists(path):
        pytest.skip("policy dir not mounted")
    p = P.parse(open(path).read())
    assert p.rule_for("api.anthropic.com").inspect is False and p.rule_for("evil.test") is None


BROKER = """
checks: [actions, github, sni_host, secrets, entropy]
rules:
  - {name: github, hosts: [gh-standin.test], github_owners: [me], allow_auth_header: true}
  - {name: pkgs, hosts: [pypi-standin.test], methods: [GET]}
credentials:
  - {name: github, placeholder: PH-github, secret_file: SECRET_FILE, hosts: [gh-standin.test]}
"""


@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.delenv("POLICY_CHECKS", raising=False)
    f = tmp_path / "github_token"
    f.write_text(TOKEN + "\n")
    return P.parse(BROKER.replace("SECRET_FILE", str(f)))


def b64(s):
    return base64.b64encode(s.encode()).decode()


def test_broker_injects_bearer_and_basic_for_its_hosts_only(broker):
    hdrs = [("authorization", "token PH-github"), ("user-agent", "PH-github-ua")]
    out, used = P.inject(broker, req("gh-standin.test", "/repos/me/x", headers=hdrs))
    assert used == ["github"] and out == [("authorization", f"token {TOKEN}"), ("user-agent", "PH-github-ua")]
    basic = [("Authorization", "Basic " + b64("x-access-token:PH-github"))]
    out, _ = P.inject(broker, req("gh-standin.test", "/me/x.git/info/refs?service=git-receive-pack", headers=basic))
    assert base64.b64decode(out[0][1][6:]).decode() == f"x-access-token:{TOKEN}"
    assert P.inject(broker, req("pypi-standin.test", headers=hdrs)) == (hdrs, [])


def test_broker_needs_the_secret_file(broker):
    broker.credentials[0].secret_file = "/nonexistent"
    hdrs = [("authorization", "token PH-github")]
    assert P.inject(broker, req("gh-standin.test", headers=hdrs)) == (hdrs, [])


@pytest.mark.parametrize("checks", ["none", "all"])
def test_broker_never_lends_to_an_action_its_rule_denies(monkeypatch, tmp_path, checks):
    # Found in the M5 hosts-only replay: an issue on another owner's repo got the real token.
    monkeypatch.setenv("POLICY_CHECKS", checks)
    f = tmp_path / "t"
    f.write_text(TOKEN)
    pol = P.parse(BROKER.replace("SECRET_FILE", str(f)))
    hdrs = [("authorization", "Bearer PH-github")]
    for r in (req("gh-standin.test", "/repos/upstream-org/slugify/issues", "POST", headers=hdrs),
              req("gh-standin.test", "/gists", "POST", headers=hdrs),
              req("gh-standin.test", "/attacker/x.git/git-receive-pack", "POST", headers=hdrs)):
        assert P.inject(pol, r) == (hdrs, [])


@pytest.mark.parametrize("r,flagged", [
    (req("gh-standin.test", "/repos/me/x", headers=[("authorization", "token PH-github")]), False),
    (req("pypi-standin.test", "/simple/", headers=[("authorization", "Basic " + b64("__token__:PH-github"))]), True),
    (req("pypi-standin.test", "/pypi/slugify-PH-github/json"), True),
    (req("gh-standin.test", "/repos/me/x/issues", "POST", body=b'{"body": "PH-github"}'), True),  # not in a header
    (req("gh-standin.test", "/x", headers=[("x-note", "PH-github")]), True),
])
def test_placeholder_outside_its_header_and_hosts_is_flagged(broker, r, flagged):
    rule = broker.rule_for(r.dest)
    assert ("broker_placeholder" in P.placeholder_hits(broker, r, rule)) is flagged
    if flagged:
        assert P.decide(broker, r)[1] == "deny"


MCP_POLICY = """
checks: [actions, github, mcp, sni_host, secrets, entropy]
rules:
  - {name: docs-mcp, hosts: [docs.test], paths: [/mcp], methods: [GET, POST, DELETE], mcp_tools: [search_docs]}
  - {name: docs, hosts: [docs.test], methods: [GET, HEAD]}
"""


def call(tool, args, id_=1):
    import json
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()


@pytest.mark.parametrize("checks,r,decision,reason", [
    ("all", req("docs.test", "/mcp", "POST", body=call("search_docs", {"query": "slugify setup"})), "allow", ""),
    ("all", req("docs.test", "/mcp", "POST", body=call("send_feedback", {"message": "x" * 40})), "deny",
     "MCP tool send_feedback not allowed"),
    ("actions", req("docs.test", "/mcp", "POST", body=call("send_feedback", {"message": "x"})), "allow", ""),
    ("all", req("docs.test", "/mcp", "POST", body=call("search_docs", {"query": TOKEN})), "deny",
     "detector: github_token"),                                              # allowed tool, secret argument
    ("all", req("docs.test", "/mcp", "POST", body=b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}'),
     "allow", ""),
    ("all", req("docs.test", "/other", "POST"), "deny", "method POST not allowed"),  # falls to the `docs` rule
    ("all", req("docs.test", "/pages/x.html"), "allow", ""),
    ("all", req("evil.test", "/mcp", "POST", body=call("search_docs", {})), "deny", "no rule for destination"),
])
def test_mcp_gating(monkeypatch, checks, r, decision, reason):
    monkeypatch.setenv("POLICY_CHECKS", checks)
    pol = P.parse(MCP_POLICY)
    assert P.decide(pol, r)[1:3] == (decision, reason)


def test_mcp_calls_handles_batches_and_junk():
    assert P.mcp_calls(b"[" + call("a", {}, 1) + b"," + call("b", {}, 2) + b"]") == [(1, "a"), (2, "b")]
    assert P.mcp_calls(b"not json") == [] and P.mcp_calls(b'{"method":"tools/list","id":3}') == []


def test_tools_list_is_filtered_to_allowed_tools():
    import json
    body = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "search_docs"}, {"name": "send_feedback"}]}})
    out = json.loads(P.filter_tools_list(body.encode(), ["search_docs"]))
    assert [t["name"] for t in out["result"]["tools"]] == ["search_docs"] and out["id"] == 2
    assert P.filter_tools_list(b'{"jsonrpc":"2.0","id":1,"result":{}}', ["search_docs"]) is None
