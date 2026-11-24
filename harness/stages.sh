#!/usr/bin/env bash
# M4 "one rule at a time": replay every fixture under proxy-enforce with the policy's checks
# turned on cumulatively. The host allowlist is always on. Rows go to results/proxy-enforce-stages.csv.
set -euo pipefail
cd "$(dirname "$0")/.."
checks=""
for stage in none actions github mcp sni_host secrets entropy; do
  [[ $stage != none ]] && checks="${checks:+$checks,}$stage"
  echo "== stage: hosts${checks:+ + $checks}" >&2
  POLICY_CHECKS="${checks:-none}" python3 harness/run.py --setup proxy-enforce --mode replay --runs 1 \
    --label "enforce:hosts${checks:+,$checks}" --out proxy-enforce-stages "$@" 2>&1 | grep " run " | sed "s/^/[${stage}] /"
done
