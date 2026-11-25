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
| M1 | Claude Code's built-in sandbox baseline | done: replay leaks 3/9, all through the allowed broad domain (gist, issue, fronting) |
| M2 | mitmproxy sidecar in observe mode, with its own CA | done: every flow logged, including the fronted request's SNI/Host mismatch; nothing blocked |
| M3 | whole-process boundary: a local MCP server's traffic goes through the proxy | done: MCP server flows logged and labeled `process: mcp-pkginfo`; a server that skips the proxy fails closed |
| M4 | policy engine and detectors in enforce mode | done: replay leaks 0/10 with every check on; the host allowlist alone leaves 5/10 |
| M5 | credential broker | done: the agent holds a placeholder; with only the host allowlist the GitHub token leaked 0/10 (5/10 without the broker) |
| M6 | MCP tool-call gating | done: per-tool rules for remote MCP servers; a shapeless secret through an allowed server's other tool leaks 3/3 without them, 0 with |
| M7 | evaluation and [`RESULTS.md`](RESULTS.md) | done except the week of real use (`bin/daily.sh`): replay leaks 33/33 → sandbox 15/33 → enforce 0/33; about +4 ms per request |
| prototype | DNS walled garden + transparent proxy ([setups/proxy-dns](setups/proxy-dns/README.md)) | works: no proxy settings in the agent, replay 0/33, Node `fetch` caught; uses [dns-cache](https://github.com/s4steve/dns-cache) |

## How it works

```
 agent container ──────────────► sink (plays the attacker; logs every request with its TLS SNI)
 Claude Code, git, curl, pip      docs.test  evil.test  collector.test  gh-standin.test  pypi-standin.test
```

From M2 on, the agent sits on an internal-only Docker network and its only way out is the proxy.

- **Fixtures** (`fixtures/`): 11 injected READMEs, issues, web pages, code comments and MCP tool results. Each one
  tries to get a fake secret out over a different path: a new host, a URL query, a POST body, a
  request header, a GitHub-style write, a fronted request, a pip index URL, a local MCP
  server's tool call (`agent/mcp/`) or another tool on an allowed remote MCP server.
- **Canaries** (`harness/canaries.py`): fresh fake secrets for every run, shaped like AWS,
  GitHub, Stripe, Slack and SSH keys. A run leaked if any of them reaches the sink, raw or
  URL-encoded, hex or base64.
- **Two modes**:
  - `replay` runs each fixture's own exfiltration command directly. It stands in for a
    compromised agent or a helper process, and measures only the network layer.
  - `agent` runs `claude -p` on the fixture. It measures whether the model obeys the injection
    and whether the network lets it through.
- **`gh-standin.test`** stands in for github.com. Tests never write to real public services.

[docs/dataflow.html](docs/dataflow.html) is a diagram of how a request flows through the system
(open it in a browser). [docs/ENTERPRISE.md](docs/ENTERPRISE.md) covers deploying it for many developers
and other agents (Codex, Cursor, Antigravity). See [docs/DESIGN.md](docs/DESIGN.md) for the full design and
[docs/DECISIONS.md](docs/DECISIONS.md) for the doc checks, decisions and findings.

## Running it

Needs Docker Desktop and the Claude Code CLI on the host. Nothing else is installed on the host.

1. Create the test CAs. They live in `~/.agent-egress-ca/`, outside the repo:

   ```bash
   bash ca/scripts/make-sink-ca.sh
   ```

   ```bash
   bash ca/scripts/make-proxy-ca.sh
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

   Swap in `--setup sandbox`, `--setup proxy-observe`, `--setup proxy-enforce` or
   `--setup proxy-broker` for the other setups. `bash harness/stages.sh` replays every fixture with the policy's checks turned on one
   at a time. The policy is `proxy/policy/policy.yaml`; edits apply without a restart.

   Results go to `results/<setup>.csv`. Transcripts go to `results/transcripts/`, which is
   gitignored.

4. Report, latency, and the false-positive study:

   ```bash
   python3 harness/report.py
   ```

   ```bash
   bash harness/latency.sh
   ```

   ```bash
   bin/daily.sh ~/path/to/a/personal/repo
   ```

   `daily.sh` runs Claude Code interactively behind the proxy in observe mode, logging to
   `proxy/daily-log/`. Add `--daily proxy/daily-log/flows.jsonl` to the report after a week.

5. Tests:

   ```bash
   python3 -m unittest tests/test_scan.py
   ```

   ```bash
   docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml run --rm -T --no-deps proxy python -m pytest -q /addons/tests
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
compose.yaml        agent + sink (the "none" setup); setups/ layer on top
agent/              agent image and fixture entrypoint
sink/               attacker server
proxy/              mitmproxy image, egress addon, policy engine, policy.yaml and tests
ca/scripts/         sink CA creation and trust removal
setups/             per-setup compose overrides and settings (sandbox, proxy-observe, proxy-enforce,
                    proxy-broker, proxy-dns prototype, proxy-port experiment)
fixtures/           injection fixtures; _base/repo is the shared tiny project
harness/            canaries, leak scanner, runner, staged runs, latency, report
bin/daily.sh        real use behind the proxy (observe mode), for the false-positive study
tests/              scanner tests
results/            CSV results per setup
docs/               DESIGN.md, DECISIONS.md, ENTERPRISE.md, dataflow.html (diagram)
```

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) ([official text](https://polyformproject.org/licenses/noncommercial/1.0.0/)).
You may use, copy, modify and share this project for any noncommercial purpose, including
personal study, research, hobby projects, and use by charities, schools and public bodies.
Commercial use needs separate permission from the author. This is a source-available license,
not an OSI open-source one. Third-party components (mitmproxy, Claude Code, Debian and Python
packages) keep their own licenses.
