#!/usr/bin/env bash
# M7 added latency: the same small HTTPS GET (a page served by the sink) from the agent container,
# direct (setup none) and through the proxy (observe, enforce). The sink is local, so the
# difference is the proxy's cost. Two cases:
#   fresh   a new curl per request: TCP + TLS to the proxy, CONNECT, and the proxy's TLS upstream
#   reused  one curl, many URLs on one connection (the first transfer is dropped)
# Writes results/latency.csv: setup,case,seconds
set -euo pipefail
cd "$(dirname "$0")/.."
N=${N:-40}
URL=https://docs.test/pages/page-image-query/page.html
out=results/latency.csv
echo "setup,case,seconds" > "$out"
for setup in none proxy-observe proxy-enforce; do
  case $setup in
    none) files=(-f compose.yaml) ;;
    proxy-observe) files=(-f compose.yaml -f setups/proxy-observe/compose.yaml) ;;
    proxy-enforce) files=(-f compose.yaml -f setups/proxy-observe/compose.yaml -f setups/proxy-enforce/compose.yaml) ;;
  esac
  svc=(sink); [[ $setup != none ]] && svc+=(proxy)
  POLICY_CHECKS=all docker compose "${files[@]}" up -d "${svc[@]}" >/dev/null 2>&1
  sleep 3
  POLICY_CHECKS=all docker compose "${files[@]}" --profile run run --rm -T agent shell bash -s 2>/dev/null <<IN \
    | sed "s/^/$setup,/" >> "$out"
for i in \$(seq $N); do printf 'fresh,'; curl -s -o /dev/null -w '%{time_total}\n' $URL; done
args=(); for i in \$(seq $((N + 1))); do args+=(-o /dev/null $URL); done
curl -s -w '%{time_total}\n' "\${args[@]}" | tail -n +2 | sed 's/^/reused,/'
IN
done
wc -l "$out"
