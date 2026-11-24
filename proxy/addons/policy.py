"""Egress policy: rules decide which actions are allowed; detectors look at what is being sent.

Pure functions over plain values, so they can be tested without a proxy. egress.py wires them
into mitmproxy. Request bodies and header values are scanned in memory and never logged.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ruamel.yaml import YAML

ALL_CHECKS = ("actions", "github", "mcp", "sni_host", "secrets", "entropy")
READ_METHODS = {"GET", "HEAD", "OPTIONS"}

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})"),
    "stripe_key": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
SPLIT = re.compile(r"[/?&=,;:\s]+")
# ponytail: fixed threshold. Hex (max 4.0 bits/char) never trips it, so hashes and SHAs pass,
# and hex-encoded secrets get through too. Tokens also need both upper- and lower-case letters
# and no "." (base64 has neither problem): long lowercase wheel filenames such as
# charset_normalizer-3.4.2-cp311-...-manylinux_2_17_aarch64.whl tripped it in the first enforce
# work session. Base32 and lowercase-only encodings get through. Tune with M7's data.
ENTROPY_MIN_LEN, ENTROPY_MIN_BITS = 20, 4.3
BODY_SCAN_LIMIT = 1 << 20


@dataclass
class Rule:
    name: str
    hosts: list[str]
    methods: list[str] | None = None
    paths: list[str] | None = None
    github_owners: list[str] | None = None
    mcp_tools: list[str] | None = None   # M6: remote MCP endpoint; tools/call only for these tools
    inspect: bool = True
    allow_auth_header: bool = False

    def matches(self, host: str) -> bool:
        host = host.lower()
        return any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in self.hosts)

    def covers(self, host: str, path: str) -> bool:
        """Host matches and, if the rule lists `paths`, the bare path matches one of them."""
        return self.matches(host) and (not self.paths or any(fnmatch.fnmatchcase(path, p) for p in self.paths))


@dataclass
class Credential:
    """A secret only the proxy holds (M5). The agent holds `placeholder` instead; the proxy swaps
    it for the secret in `headers` on requests to `hosts` that the policy allows, and nowhere else."""
    name: str
    placeholder: str
    secret_file: str
    hosts: list[str]
    headers: list[str] = field(default_factory=lambda: ["authorization"])

    def matches(self, host: str) -> bool:
        return Rule(self.name, self.hosts).matches(host)

    def secret(self) -> str | None:
        try:
            return Path(self.secret_file).read_text().strip() or None
        except OSError:
            return None


@dataclass
class Policy:
    rules: list[Rule]
    checks: frozenset[str]
    credentials: list[Credential] = field(default_factory=list)

    def rule_for(self, host: str, path: str | None = None) -> Rule | None:
        """First rule covering host and path. Without a path (a CONNECT), any rule for the host."""
        if path is None:
            return next((r for r in self.rules if r.matches(host)), None)
        bare = urlsplit(path).path
        return next((r for r in self.rules if r.covers(host, bare)), None)


def parse(text: str) -> Policy:
    d = YAML(typ="safe").load(text) or {}
    env = os.environ.get("POLICY_CHECKS", "all")
    checks = frozenset(d.get("checks", ALL_CHECKS) if env == "all" else
                       () if env == "none" else env.split(","))
    if unknown := checks - set(ALL_CHECKS):
        raise ValueError(f"unknown checks: {sorted(unknown)}")
    return Policy([Rule(**r) for r in d.get("rules", [])], checks,
                  [Credential(**c) for c in d.get("credentials", [])])


class PolicyFile:
    """Reloads on mtime change. A bad edit keeps the previous policy (and reports it once)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.mtime = self.path.stat().st_mtime
        self.policy = parse(self.path.read_text())  # no fallback at startup: fail closed
        self.error: str | None = None

    def get(self) -> Policy:
        try:
            mtime = self.path.stat().st_mtime
            if mtime != self.mtime:
                self.mtime = mtime
                self.policy, self.error = parse(self.path.read_text()), None
        except Exception as e:  # noqa: BLE001  keep enforcing the last good policy
            self.error = f"{type(e).__name__}: {e}"
        return self.policy


def github_allows(method: str, path: str, owners: list[str]) -> tuple[bool, str]:
    """Reads and clones anywhere; pushes and API writes only to `owners`' repos.

    Works for github.com (/owner/repo/...) and api.github.com (/repos/owner/repo/...).
    """
    url = urlsplit(path)
    parts = [p for p in url.path.split("/") if p]
    owned = {o.lower() for o in owners}
    if parts[-1:] == ["git-upload-pack"]:
        return True, "git fetch"
    if parts[-1:] == ["git-receive-pack"] or "service=git-receive-pack" in url.query:
        ok = bool(parts) and parts[0].lower() in owned
        return ok, "git push to own repo" if ok else "git push to another owner's repo"
    if method.upper() in READ_METHODS:
        return True, "read"
    if parts[:1] == ["repos"] and len(parts) > 1 and parts[1].lower() in owned:
        return True, "API write to own repo"
    return False, "write outside own repos"


def _decoded(text: str) -> list[str]:
    """The text, plus the decoding of every base64-looking token in it (std and urlsafe)."""
    out = [text]
    for tok in B64_TOKEN.findall(text):
        t = tok.rstrip("=").replace("-", "+").replace("_", "/")
        try:
            out.append(base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8"))
        except (binascii.Error, ValueError):
            pass
    return out


def find_secrets(text: str) -> set[str]:
    return {name for chunk in _decoded(text) for name, rx in SECRET_PATTERNS.items() if rx.search(chunk)}


def entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def high_entropy_tokens(text: str) -> list[str]:
    return [t for t in SPLIT.split(text)
            if len(t) >= ENTROPY_MIN_LEN and "." not in t and t.lower() != t and t.upper() != t
            and entropy(t) >= ENTROPY_MIN_BITS]


def url_texts(path: str) -> list[str]:
    url = urlsplit(path)
    # unquote, not parse_qsl: a raw "+" in a base64 value must stay a "+".
    return [unquote(url.path)] + [unquote(kv.partition("=")[2]) for kv in url.query.split("&") if kv]


def basic_auth_text(value: str) -> str:
    if value[:6].lower() == "basic ":
        try:
            return value + " " + base64.b64decode(value[6:]).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            pass
    return value


@dataclass
class Request:
    method: str
    dest: str            # where the bytes actually go: the CONNECT target / upstream host
    host: str            # Host header
    sni: str | None
    path: str            # with query
    headers: list[tuple[str, str]]
    body: bytes = b""


def detect(req: Request, rule: Rule | None) -> list[str]:
    """Detector names that fired. Never returns the matched values."""
    if rule is not None and not rule.inspect:
        return []
    hits = []
    if req.host.lower() != req.dest.lower() or (req.sni and req.sni.lower() != req.dest.lower()):
        hits.append("sni_host")
    texts = url_texts(req.path)
    texts += [basic_auth_text(v) for k, v in req.headers
              if k.lower() not in {"host", "proxy-authorization"}
              and not (k.lower() == "authorization" and rule and rule.allow_auth_header)]
    texts.append(req.body[:BODY_SCAN_LIMIT].decode("utf-8", "replace"))
    hits += sorted({s for t in texts for s in find_secrets(t)})
    if any(high_entropy_tokens(t) for t in url_texts(req.path)):
        hits.append("entropy")
    return hits


def placeholder_hits(policy: Policy, req: Request, rule: Rule | None) -> list[str]:
    """A credential placeholder anywhere except an injectable header to that credential's hosts.
    The placeholder is worthless to an attacker, but sending it elsewhere shows intent."""
    if rule is not None and not rule.inspect:
        return []
    hits = []
    for c in policy.credentials:
        allowed = c.matches(req.dest)
        other = url_texts(req.path) + [req.body[:BODY_SCAN_LIMIT].decode("utf-8", "replace")]
        other += [basic_auth_text(v) for k, v in req.headers if not (allowed and k.lower() in c.headers)]
        if any(c.placeholder in t for t in other):
            hits.append("broker_placeholder")
    return hits


def _swap(value: str, old: str, new: str) -> str:
    if value[:6].lower() == "basic ":
        try:
            raw = base64.b64decode(value[6:]).decode("utf-8")
        except (binascii.Error, ValueError):
            return value
        return value[:6] + base64.b64encode(raw.replace(old, new).encode()).decode()
    return value.replace(old, new)


def lends_credential(policy: Policy, req: Request) -> bool:
    """The rule's own methods, paths and GitHub owners, whatever `checks` says. The broker never
    lends a credential to an action its rule doesn't allow, even while those checks are off."""
    rule = policy.rule_for(req.dest, req.path)
    if rule is None or (rule.methods and req.method.upper() not in rule.methods):
        return False
    if rule.mcp_tools is not None and any(t not in rule.mcp_tools for _, t in mcp_calls(req.body)):
        return False
    return rule.github_owners is None or github_allows(req.method, req.path, rule.github_owners)[0]


def inject(policy: Policy, req: Request) -> tuple[list[tuple[str, str]], list[str]]:
    """Swap placeholders for secrets in the credential's headers, for its hosts and its rule's
    allowed actions only. Returns the new headers and the names of the credentials used."""
    headers, used = req.headers, []
    if not lends_credential(policy, req):
        return headers, used
    for c in policy.credentials:
        if not c.matches(req.dest) or not any(k.lower() in c.headers and c.placeholder in basic_auth_text(v)
                                              for k, v in headers):
            continue
        if (secret := c.secret()) is None:
            continue
        headers = [(k, _swap(v, c.placeholder, secret) if k.lower() in c.headers else v) for k, v in headers]
        used.append(c.name)
    return headers, used


def check_of(hit: str) -> str:
    return hit if hit in ("sni_host", "entropy") else "secrets"


def decide(policy: Policy, req: Request) -> tuple[str | None, str, str, list[str]]:
    """(rule name, "allow" | "deny", reason, detector hits). Hits are reported even when their
    check is off; only enabled checks deny."""
    rule = policy.rule_for(req.dest, req.path)
    hits = detect(req, rule) + placeholder_hits(policy, req, rule)
    if rule is None:
        return None, "deny", "no rule for destination" if policy.rule_for(req.dest) is None else "no rule for path", hits
    on = policy.checks
    if "actions" in on:
        if rule.methods and req.method.upper() not in rule.methods:
            return rule.name, "deny", f"method {req.method} not allowed", hits
    if "github" in on and rule.github_owners is not None:
        ok, why = github_allows(req.method, req.path, rule.github_owners)
        if not ok:
            return rule.name, "deny", why, hits
    if "mcp" in on and rule.mcp_tools is not None:
        for _, tool in mcp_calls(req.body):
            if tool not in rule.mcp_tools:
                return rule.name, "deny", f"MCP tool {tool} not allowed", hits
    if blocking := [h for h in hits if check_of(h) in on]:
        return rule.name, "deny", "detector: " + ",".join(blocking), hits
    return rule.name, "allow", "", hits


def redact_path(path: str) -> str:
    """Path without query, with secret-shaped and high-entropy segments replaced, for the log."""
    segs = urlsplit(path).path.split("/")
    return "/".join("<redacted>" if s and (find_secrets(unquote(s)) or high_entropy_tokens(unquote(s))) else s
                    for s in segs)


def _jsonrpc(body: bytes) -> list[dict]:
    try:
        msg = json.loads(body)
    except ValueError:
        return []
    return [m for m in (msg if isinstance(msg, list) else [msg]) if isinstance(m, dict)]


def mcp_calls(body: bytes) -> list[tuple[object, str]]:
    """(JSON-RPC id, tool name) for each tools/call in an MCP request body (single or batch)."""
    return [(m.get("id"), str((m.get("params") or {}).get("name"))) for m in _jsonrpc(body)
            if m.get("method") == "tools/call"]


def filter_tools_list(body: bytes, allowed: list[str]) -> bytes | None:
    """A JSON tools/list response with only the allowed tools, or None if there's nothing to change.
    The agent never learns about tools it can't call. SSE responses aren't filtered."""
    msgs, changed = _jsonrpc(body), False
    for m in msgs:
        tools = (m.get("result") or {}).get("tools") if isinstance(m.get("result"), dict) else None
        if isinstance(tools, list):
            kept = [t for t in tools if isinstance(t, dict) and t.get("name") in allowed]
            changed |= len(kept) != len(tools)
            m["result"]["tools"] = kept
    if not changed:
        return None
    return json.dumps(msgs if body.lstrip()[:1] == b"[" else msgs[0]).encode()
