#!/usr/bin/env python3
"""Print the M7 result tables as markdown, from results/*.csv and (optionally) a proxy flow log.

    python3 harness/report.py                                   # leak rates, stages, latency
    python3 harness/report.py --daily proxy/daily-log/flows.jsonl   # + false positives from real use
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
SETUPS = ["none", "sandbox", "proxy-observe", "proxy-enforce", "proxy-broker", "proxy-dns"]


def rows(name: str) -> list[dict]:
    p = RESULTS / f"{name}.csv"
    return list(csv.DictReader(p.open())) if p.exists() else []


def table(head: list[str], body: list[list]) -> str:
    return "\n".join(["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
                     + ["| " + " | ".join(str(c) for c in r) + " |" for r in body])


def replay() -> str:
    data = rows("final-replay")
    by = defaultdict(lambda: defaultdict(list))
    for r in data:
        by[r["fixture"]][r["setup"]].append(int(r["leaked"]))
    setups = [s for s in SETUPS if any(s in v for v in by.values())]
    body = [[f] + [f"{sum(by[f][s])}/{len(by[f][s])}" if by[f][s] else "" for s in setups] for f in sorted(by)]
    tot = [sum(sum(by[f][s]) for f in by) for s in setups]
    n = [sum(len(by[f][s]) for f in by) for s in setups]
    body.append(["**runs that leaked**"] + [f"**{t}/{k}**" for t, k in zip(tot, n)])
    body.append(["**fixtures that ever leaked**"] + [f"**{sum(any(by[f][s]) for f in by)}/{len(by)}**" for s in setups])
    return table(["fixture"] + setups, body)


def agent() -> str:
    body = []
    for s in SETUPS:
        a = [r for r in rows(s) if r["mode"] == "agent"]
        if a:
            cost = sum(float(r["cost_usd"] or 0) for r in a)
            body.append([s, len(a), len({r["fixture"] for r in a}), sum(int(r["attempted"]) for r in a),
                         sum(int(r["leaked"]) for r in a), f"${cost:.2f}"])
    return table(["setup", "runs", "fixtures", "attempted", "leaked", "notional cost"], body)


def stages() -> str:
    latest: dict[tuple[str, str], int] = {}
    order: list[str] = []
    for r in rows("final-stages"):
        latest[(r["setup"], r["fixture"])] = int(r["leaked"])
        if r["setup"] not in order:
            order.append(r["setup"])
    body = []
    for label in order:
        fx = {f: v for (l, f), v in latest.items() if l == label}
        body.append([label.removeprefix("enforce:"), f"{sum(fx.values())}/{len(fx)}",
                     ", ".join(sorted(f for f, v in fx.items() if v)) or "-"])
    return table(["checks on (host allowlist always)", "leaked", "still leaking"], body)


def latency() -> str:
    data = defaultdict(list)
    for r in rows("latency"):
        data[(r["setup"], r["case"])].append(float(r["seconds"]) * 1000)
    if not data:
        return "_no results/latency.csv; run harness/latency.sh_"
    body = []
    for case in ("fresh", "reused"):
        base = statistics.median(data[("none", case)]) if data[("none", case)] else None
        for s in ("none", "proxy-observe", "proxy-enforce"):
            v = sorted(data[(s, case)])
            if not v:
                continue
            p50, p95 = statistics.median(v), v[min(len(v) - 1, round(0.95 * (len(v) - 1)))]
            added = f"+{p50 - base:.1f}" if base is not None and s != "none" else ""
            body.append([case, s, len(v), f"{p50:.1f}", f"{p95:.1f}", added])
    return table(["connection", "setup", "n", "p50 ms", "p95 ms", "added p50 ms"], body)


def daily(path: Path) -> str:
    flows, events = [], Counter()
    for line in path.open():
        r = json.loads(line)
        events[r.get("event")] += 1
        if r.get("event") == "flow":
            flows.append(r)
    if not flows:
        return "_no flows yet_"
    t0, t1 = min(r["time"] for r in flows), max(r["time"] for r in flows)
    dec = Counter(r.get("decision") for r in flows)
    out = [f"{len(flows)} flows over {(t1 - t0) / 86400:.1f} days; would allow {dec['allow']}, "
           f"would deny {dec['deny']} ({100 * dec['deny'] / len(flows):.2f}%). "
           f"TLS failures (a tool rejecting the proxy CA): {events['tls_failed_client']}.", ""]
    denies = Counter((r.get("reason") or "", r.get("dest") or r["host"], r["method"]) for r in flows
                     if r.get("decision") == "deny")
    out.append(table(["would-deny reason", "destination", "method", "count"],
                     [[*k, v] for k, v in denies.most_common(40)]) if denies else "_no would-deny flows_")
    hosts = Counter(r.get("dest") or r["host"] for r in flows)
    out += ["", table(["destination", "flows"], [[h, n] for h, n in hosts.most_common(25)])]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--daily", type=Path, help="flow log from bin/daily.sh (observe mode, real use)")
    a = ap.parse_args()
    print("## Leak rate, replay (results/final-replay.csv)\n\n" + replay())
    print("\n## Leak rate, agent mode (all agent rows in results/<setup>.csv)\n\n" + agent())
    print("\n## One check at a time (results/final-stages.csv, replay)\n\n" + stages())
    print("\n## Added latency (results/latency.csv)\n\n" + latency())
    if a.daily:
        print(f"\n## False positives from real use ({a.daily})\n\n" + daily(a.daily))


if __name__ == "__main__":
    main()
