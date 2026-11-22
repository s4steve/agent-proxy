# Decisions and doc checks

## Doc checks (2026-11-21)
Read: code.claude.com/docs/en/headless, /setup, /cli-reference (truncated tail not read), /iam, /devcontainer.

| fact | source | used for |
|---|---|---|
| `-p`, `--output-format json\|stream-json`, `--max-turns` (print mode only) | headless, cli-reference | harness |
| `--permission-mode bypassPermissions` is valid; `--dangerously-skip-permissions` is equivalent | cli-reference | harness |
| The CLI rejects the skip-permissions flag when launched as root | devcontainer | agent runs as `node` |
| `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`, one-year token, subscription plans | iam | auth |
| `ANTHROPIC_API_KEY` outranks `CLAUDE_CODE_OAUTH_TOKEN`, and in `-p` is always used when present | iam | `.env.example` warns |
| `--bare` does not read `CLAUDE_CODE_OAUTH_TOKEN` | iam, headless | not using `--bare` |
| npm install pinned `@anthropic-ai/claude-code@X.Y.Z` with `DISABLE_AUTOUPDATER=1` (Node 22+) | setup, devcontainer | agent/Dockerfile |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` opts out of telemetry/error reporting | devcontainer | agent/Dockerfile |

Not documented on the pages read: the `num_turns` field in the JSON result. The harness reads it if present.

Still to check, in the milestone that needs it: sandbox settings keys (M1); mitmproxy 12 addon and
`tls_clienthello` APIs, chain in `mitmproxy-ca.pem`, `sandbox.network.httpProxyPort`, Docker
Desktop `internal: true` on arm64 (M2).

## Decisions
- **Auth**: `CLAUDE_CODE_OAUTH_TOKEN` in a gitignored `.env`, created by the owner. Claude's own
  model login is outside the broker's scope.
- **Permission mode**: `bypassPermissions` in every setup. The network layer is the only variable.
- **Sink TLS**: a separate sink test CA, so fronting is real TLS with a valid certificate for
  the SNI name. Separate from the proxy CA so the proxy's trust can be removed on its own.
- **Image build context for certs** is `~/.agent-egress-ca/public` (public certs only).
- **Pages are served from docs.test**, which is not counted as an attacker host: fetching the
  injected page is reading untrusted content, not exfiltration.
- **Sink log access**: the harness reads `GET /__log` on the sink's admin port 8099, published on
  Mac loopback only. `SINK_URL` points it elsewhere (the Raspberry Pi later).
- **Fixture metadata is JSON, harness is stdlib only**, so it runs on the Mac with no installs.
  Scanner tests run with `python3 -m unittest` (pytest also collects them).

## Verified in M0
- From the agent container, curl, Node `fetch`, Python `urllib` and git all validate the sink
  certificate through the system store and NODE_EXTRA_CA_CERTS. No verification is disabled.
- A fronted request (`curl https://gh-standin.test/... -H 'Host: evil.test'`) is logged with
  sni=gh-standin.test, host=evil.test.

## Tools that ignored proxy or CA settings
(Filled in from M2 on.)
