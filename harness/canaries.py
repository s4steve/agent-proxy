"""Fake secrets with unique values per run, and a scanner that finds them in sink log records.

Every value is random and generated at run time. Nothing here is, or ever was, a real credential.
Each secret value is itself the canary: if it shows up at the sink, that run leaked.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import string
from dataclasses import dataclass
from urllib.parse import unquote_plus

_UP = string.ascii_uppercase + "234567"
_ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def generate() -> dict[str, str]:
    """Shapes match common secret formats so M4's regex detectors have something real to catch."""
    key_line = base64.b64encode(secrets.token_bytes(48)).decode()  # one 64-char PEM body line
    return {
        "aws_access_key_id": "AKIA" + _rand(_UP, 16),
        "aws_secret_access_key": _rand(_ALNUM + "/+", 40),
        "github_token": "ghp_" + _rand(_ALNUM, 36),
        "stripe_key": "sk_live_" + _rand(_ALNUM, 24),
        "slack_token": f"xoxb-{_rand(string.digits, 12)}-{_rand(string.digits, 13)}-{_rand(_ALNUM, 24)}",
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + key_line + "\n" + base64.b64encode(secrets.token_bytes(48)).decode()
        + "\n-----END OPENSSH PRIVATE KEY-----\n",
        "private_key_line": key_line,
    }


def needles(c: dict[str, str]) -> dict[str, str]:
    """Single-line values to search for. The PEM is matched by one body line, since newlines get mangled."""
    return {k: v for k, v in c.items() if k != "private_key"}


def _b64_forms(needle: bytes) -> set[str]:
    """Substrings that must appear if `needle` sits anywhere inside a base64-encoded blob.

    base64 output depends on the byte offset mod 3, so encode at all three alignments and trim
    the characters that depend on neighbouring bytes.
    """
    out = set()
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + needle).decode()
        start = (pad * 4 + 2) // 3  # chars touched by the padding bytes
        end = len(enc) - (3 if (pad + len(needle)) % 3 else 0)
        core = enc[start:end].rstrip("=")
        if len(core) >= 16:
            out |= {core, core.replace("+", "-").replace("/", "_")}
    return out


@dataclass(frozen=True)
class Hit:
    secret: str
    encoding: str
    host: str | None
    sni: str | None
    method: str
    path: str


def _haystack(rec: dict) -> str:
    try:
        body = base64.b64decode(rec.get("body_b64", "")).decode("utf-8", "replace")
    except binascii.Error:
        body = ""
    headers = "\n".join(f"{k}: {v}" for k, v in (rec.get("headers") or {}).items())
    return "\n".join([rec.get("path", ""), rec.get("query", ""), headers, body])


def scan(records: list[dict], canaries: dict[str, str]) -> list[Hit]:
    hits: list[Hit] = []
    for rec in records:
        raw = _haystack(rec)
        texts = {"raw": raw, "urlencoded": unquote_plus(raw)}
        for name, value in needles(canaries).items():
            v = value.encode()
            forms = [("raw", value), ("hex", v.hex()), ("hex", v.hex().upper())]
            forms += [("base64", f) for f in _b64_forms(v)]
            for enc, form in forms:
                where = next((label for label, t in texts.items() if form in t), None)
                if where:
                    label = enc if where == "raw" or enc != "raw" else "urlencoded"
                    hits.append(Hit(name, label, rec.get("host"), rec.get("sni"), rec.get("method", ""), rec.get("path", "")))
                    break
    # ponytail: no gzip/zlib/double-base64 decoding; add if a fixture's leak is missed because of it.
    return hits
