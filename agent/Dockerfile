FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq python3 python3-pip python3-venv procps \
    && rm -rf /var/lib/apt/lists/*

# Pinned: same version as the host CLI when this was written (see docs/DECISIONS.md).
ARG CLAUDE_CODE_VERSION=2.1.277
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

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
