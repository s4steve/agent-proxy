FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq python3 python3-pip python3-venv procps \
      bubblewrap socat ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Pinned: same version as the host CLI when this was written (see docs/DECISIONS.md).
ARG CLAUDE_CODE_VERSION=2.1.277
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}
# The sandbox engine Claude Code is built on, as a CLI (`srt`). Replay mode under the
# "sandbox" setup runs fixture commands through it, so no model is in the loop.
ARG SANDBOX_RUNTIME_VERSION=0.0.83
RUN npm install -g @anthropic-ai/sandbox-runtime@${SANDBOX_RUNTIME_VERSION}

# Trust anchors. The `ca` build context is ~/.agent-egress-ca/public (outside the repo,
# public certs only), so no CA key is ever sent to the builder or enters an image.
COPY --from=ca sink-ca.pem /usr/local/share/ca-certificates/agent-egress-sink.crt
RUN update-ca-certificates

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-egress-sink.crt \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# bypassPermissions is rejected as root, so the agent runs as the image's `node` user.
USER node
WORKDIR /home/node
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
