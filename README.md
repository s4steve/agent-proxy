# Agent Egress Firewall

An egress firewall for coding agents, and a harness that measures whether it works.

A coding agent reads untrusted content (READMEs, issues, web pages), holds private data (code,
`.env` files, tokens) and can send data out. Together those make the "lethal trifecta": a prompt
injection can make the agent leak secrets. A hostname allowlist doesn't stop this once a broad
domain like github.com is allowed, because gists, issues and pushes to someone else's repo all
live there.

The thesis under test: **allowlist the action, not the domain.** A TLS-terminating proxy can
decide on host, method, path and GitHub repo owner, and inspect what is being sent.

This is a personal learning project. Readable code and honest measurements come first.

## Status

| milestone | what | state |
|---|---|---|
| M0 | fixtures, canaries, sink, harness; the unprotected "none" baseline | done: replay leaks 9/9; agent leaks 0/27 (the model refused every injection) |
| M1 | Claude Code's built-in sandbox baseline | next |
| M2 | mitmproxy sidecar in observe mode, with its own CA | |
| M3 | whole-process boundary: a local MCP server's traffic goes through the proxy | |
| M4 | policy engine and detectors in enforce mode | |
| M5 | credential broker | |
| M6 | MCP tool-call gating | |
| M7 | evaluation and `RESULTS.md` | |

## How it works

```
 agent container ──────────────► sink (plays the attacker; logs every request with its TLS SNI)
 Claude Code, git, curl, pip      docs.test  evil.test  collector.test  gh-standin.test  pypi-standin.test
```

From M2 on, the agent sits on an internal-only Docker network and its only way out is the proxy.

- **Fixtures** (`fixtures/`): 9 injected READMEs, issues, web pages and code comments. Each one
  tries to get a fake secret out over a different path: a new host, a URL query, a POST body, a
  request header, a GitHub-style write, a fronted request or a pip index URL.
- **Canaries** (`harness/canaries.py`): fresh fake secrets for every run, shaped like AWS,
  GitHub, Stripe, Slack and SSH keys. A run leaked if any of them reaches the sink, raw or
  URL-encoded, hex or base64.
- **Two modes**:
  - `replay` runs each fixture's own exfiltration command directly. It stands in for a
    compromised agent or a helper process, and measures only the network layer.
  - `agent` runs `claude -p` on the fixture. It measures whether the model obeys the injection
    and whether the network lets it through.
- **`gh-standin.test`** stands in for github.com. Tests never write to real public services.

See [docs/DESIGN.md](docs/DESIGN.md) for the full design and
[docs/DECISIONS.md](docs/DECISIONS.md) for the doc checks, decisions and findings.

## Running it

Needs Docker Desktop and the Claude Code CLI on the host. Nothing else is installed on the host.

1. Create the sink's test CA. It lives in `~/.agent-egress-ca/`, outside the repo:

   ```bash
   bash ca/scripts/make-sink-ca.sh
   ```

2. Create a token for the agent container with `claude setup-token`, and put it in a
   gitignored `.env` (see `.env.example`):

   ```
   CLAUDE_CODE_OAUTH_TOKEN=...
   ```

3. Run the baseline:

   ```bash
   python3 harness/run.py --setup none --mode replay --runs 1
   ```

   ```bash
   python3 harness/run.py --setup none --mode agent --runs 3
   ```

   Results go to `results/<setup>.csv`. Transcripts go to `results/transcripts/`, which is
   gitignored.

4. Scanner tests:

   ```bash
   python3 -m unittest tests/test_scan.py
   ```

To remove every trust anchor, container and image this project created:

```bash
bash ca/scripts/remove-trust.sh
```

## Safety rules

- Every secret in this repo and its runs is fake and generated at run time.
- Fixtures run only against a throwaway repo created inside the agent container, never a real one.
- TLS verification is never disabled. CAs are trusted only inside the agent container, never in
  the host's keychain.
- The host's normal traffic never goes through the proxy.

## Layout

```
compose.yaml        agent + sink (proxy from M2)
agent/              agent image and fixture entrypoint
sink/               attacker server
ca/scripts/         sink CA creation and trust removal
fixtures/           injection fixtures; _base/repo is the shared tiny project
harness/            canaries, leak scanner, runner
tests/              scanner tests
results/            CSV results per setup
docs/               DESIGN.md, DECISIONS.md
```
