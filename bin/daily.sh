#!/usr/bin/env bash
# M7 false-positive study: use Claude Code for real work inside the agent container, behind the
# proxy in OBSERVE mode. Nothing is blocked; every flow is logged with the decision enforce mode
# would have made, to proxy/daily-log/flows.jsonl (gitignored). After a week:
#   python3 harness/report.py --daily proxy/daily-log/flows.jsonl
#
# Usage: bin/daily.sh <repo-dir> [claude args...]
#   <repo-dir> is mounted read-write at /home/node/work. Use personal repos only.
# Separate compose project ("agent-egress-daily") and log dir, so harness runs don't mix in.
# Your Mac's own traffic never goes through this proxy. No GitHub credentials are inside, so
# pushes fail: push from the Mac. Auth is CLAUDE_CODE_OAUTH_TOKEN from .env.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(cd "${1:?usage: bin/daily.sh <repo-dir> [claude args...]}" && pwd); shift
mkdir -p proxy/daily-log
export EGRESS_LOG_DIR=./proxy/daily-log POLICY_CHECKS=all
DC=(docker compose -p agent-egress-daily -f compose.yaml -f setups/proxy-observe/compose.yaml --profile run)
"${DC[@]}" up -d --build proxy >/dev/null
exec "${DC[@]}" run --rm -it --no-deps -v "$REPO:/home/node/work" -w /home/node/work agent shell claude "$@"
