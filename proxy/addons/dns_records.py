"""Write dns-cache local records for the agent view: every host the policy allows -> the proxy.

    python3 dns_records.py <proxy-ip> [policy.yaml] > agent.records

Wildcard hosts (*.example.com) can't be records (dns-cache matches names exactly), so they are
skipped with a warning on stderr. Only A records are written: an AAAA, HTTPS or SVCB query for
the same name gets an empty answer, so no IPv6 detour and no ECH keys or QUIC hints.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import policy  # noqa: E402

ip = sys.argv[1]
path = sys.argv[2] if len(sys.argv) > 2 else "/policy/policy.yaml"
os.environ["POLICY_CHECKS"] = "all"
pol = policy.parse(open(path).read())
print(f"# generated from {os.path.basename(path)} by dns_records.py: every allowed host -> the proxy")
seen = set()
for rule in pol.rules:
    for host in rule.hosts:
        if host.startswith("*."):
            print(f"skipped wildcard {host} (rule {rule.name})", file=sys.stderr)
        elif host not in seen:
            seen.add(host)
            print(f"{host:40} A  {ip}")
