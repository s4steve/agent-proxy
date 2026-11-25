# proxy-dns (prototype)

The agent gets **no proxy settings**. Its only resolver is a walled-garden
[dns-cache](https://github.com/s4steve/dns-cache) that answers every host the egress policy
allows with the proxy's address, and `NXDOMAIN` for everything else, without ever forwarding a
query. The proxy accepts those connections in transparent mode and picks the upstream from the
TLS SNI (or the Host header for plain HTTP), never from the address the client dialled.

This catches tools that ignore `HTTPS_PROXY` (Node's built-in `fetch`, and by report Cursor's
HTTP/2 path and Antigravity's language server), without opening DNS as a way out.

```
agent (dnsnet .128/25)  --DNS-->  dns-cache 172.31.0.3   (records only, no route out)
      |                                  github.com -> 172.31.0.2, evil.test -> NXDOMAIN
      +--TCP 443/80 to 172.31.0.2-->  proxy (transparent@443, transparent@80, regular@8080)
                                         judges SNI/Host, connects by that name --> outside
```

Needs a checkout of dns-cache next to this repo (or set `DNS_CACHE_DIR`), at a version with
`allow_only` and local records.

Run:

```bash
python3 harness/run.py --setup proxy-dns --mode replay --runs 3
```

Probe DNS, bypasses and Node `fetch` from inside the agent:

```bash
docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml -f setups/proxy-enforce/compose.yaml -f setups/proxy-dns/compose.yaml --profile run run --rm -T agent shell bash -s < setups/proxy-dns/probe.sh
```

After any change to `proxy/policy/policy.yaml` hosts, regenerate the records (wildcard hosts
can't be records and are skipped with a warning), then restart `dns`:

```bash
docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml run --rm -T --no-deps proxy python3 /addons/dns_records.py 172.31.0.2 > setups/proxy-dns/agent.records
```

`PROXY_LOG_LEVEL=debug` turns on mitmproxy's connection log (`docker logs agent-egress-proxy-1`).
Results and findings are in [docs/DECISIONS.md](../../docs/DECISIONS.md#prototype-dns-walled-garden-and-transparent-proxy-2026-11-25).
