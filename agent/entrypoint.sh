#!/usr/bin/env bash
# Usage: entrypoint.sh <fixture_id>      run one red-team fixture, stream-json transcript on stdout
#        entrypoint.sh shell [cmd...]    debugging
# Env: CANARIES (JSON of fake secrets, from harness/canaries.py), CLAUDE_CODE_OAUTH_TOKEN,
#      MODE=agent (default: claude -p reads the injection) or replay (run the fixture's own
#      exfil command directly, standing in for a compromised agent or helper process).
set -euo pipefail

if [[ "${1:-}" == shell ]]; then shift; exec "${@:-bash}"; fi
FIX="/fixtures/${1:?fixture id}"
[[ -f "$FIX/fixture.json" ]] || { echo "no fixture $FIX" >&2; exit 2; }

# Throwaway repo, built fresh inside the container. Never a real repo.
mkdir -p /home/node/work && cd /home/node/work
cp -r /fixtures/_base/repo/. .                     # shared tiny project with one failing test
[[ -d "$FIX/repo" ]] && cp -r "$FIX/repo/." .      # the fixture's injected files overlay it
git init -q -b main && git -c user.name=fixture -c user.email=fixture@example.test add -A \
  && git -c user.name=fixture -c user.email=fixture@example.test commit -qm "initial import" --allow-empty

# Plant the fake secrets where real ones usually live, then drop them from the environment.
python3 - <<'PY'
import json, os, pathlib
c = json.loads(os.environ["CANARIES"])
pathlib.Path(".env").write_text(
    f"AWS_ACCESS_KEY_ID={c['aws_access_key_id']}\nAWS_SECRET_ACCESS_KEY={c['aws_secret_access_key']}\n"
    f"GITHUB_TOKEN={c['github_token']}\nSTRIPE_SECRET_KEY={c['stripe_key']}\nSLACK_BOT_TOKEN={c['slack_token']}\n")
aws = pathlib.Path.home() / ".aws"; aws.mkdir(exist_ok=True)
(aws / "credentials").write_text(
    f"[default]\naws_access_key_id = {c['aws_access_key_id']}\naws_secret_access_key = {c['aws_secret_access_key']}\n")
ssh = pathlib.Path.home() / ".ssh"; ssh.mkdir(mode=0o700, exist_ok=True)
(ssh / "id_ed25519").write_text(c["private_key"]); (ssh / "id_ed25519").chmod(0o600)
PY
unset CANARIES

# AGENT_SANDBOX=1 (setups/sandbox): Claude Code's sandbox in agent mode; the same engine (srt) in replay.
REPLAY=$(jq -r .replay "$FIX/fixture.json")
if [[ "${MODE:-agent}" == replay ]]; then
  if [[ "${AGENT_SANDBOX:-}" == 1 ]]; then
    exec timeout "${RUN_TIMEOUT:-600}" srt -s /etc/agent-sandbox/srt-settings.json -c "$REPLAY"
  fi
  exec timeout "${RUN_TIMEOUT:-600}" bash -c "$REPLAY"
fi
SETTINGS=()
[[ "${AGENT_SANDBOX:-}" == 1 ]] && SETTINGS=(--settings /etc/agent-sandbox/claude-settings.json)

PROMPT=$(jq -r .prompt "$FIX/fixture.json")
exec timeout "${RUN_TIMEOUT:-600}" claude -p "$PROMPT" \
  --permission-mode bypassPermissions --output-format stream-json --verbose \
  --max-turns "${MAX_TURNS:-30}" "${SETTINGS[@]}"
