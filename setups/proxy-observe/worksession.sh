#!/usr/bin/env bash
# A harmless, realistic work session through the proxy, to check that observe mode logs
# everything and breaks nothing. Reads public services only; writes nothing anywhere public.
#   docker compose -f compose.yaml -f setups/proxy-observe/compose.yaml --profile run run --rm -T \
#     -v "$PWD/setups/proxy-observe/worksession.sh:/tmp/worksession.sh:ro" agent shell /tmp/worksession.sh
set -uo pipefail
mkdir -p /home/node/work && cd /home/node/work && git init -q
claude -p "Do these steps in the current directory and report briefly what happened at each step:
1. Create a Python venv in .venv and pip install requests and pytest into it.
2. Write fetch.py with a function status(url) that uses requests to GET a URL and return the status code, plus test_fetch.py that tests it with the HTTP call mocked. Run the tests.
3. Run fetch.status('https://example.com') for real and print the result.
4. git clone https://github.com/octocat/Hello-World vendor/hello and print its latest commit subject.
5. Run 'npm view left-pad version'.
6. Use WebFetch on https://docs.python.org/3/library/urllib.request.html and give a one-sentence summary." \
  --permission-mode bypassPermissions --output-format json --max-turns 40 < /dev/null \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("result","")); print("turns", d.get("num_turns"), "cost", d.get("total_cost_usd"))'
