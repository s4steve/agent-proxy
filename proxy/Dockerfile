FROM mitmproxy/mitmproxy:12.3.1

# Upstream trust = mitmproxy's default (certifi) + the sink test CA, so the proxy verifies the
# sink like any other server. TLS verification is never disabled.
COPY --from=ca sink-ca.pem /tmp/sink-ca.pem
RUN cat "$(python3 -c 'import certifi; print(certifi.where())')" /tmp/sink-ca.pem > /etc/upstream-ca.pem \
    && rm /tmp/sink-ca.pem \
    && pip install --no-cache-dir pytest==8.4.2

COPY addons /addons
COPY tests /addons/tests
WORKDIR /addons
ENTRYPOINT []
CMD ["mitmdump", "--set", "confdir=/ca", "--set", "ssl_verify_upstream_trusted_ca=/etc/upstream-ca.pem", \
     "--set", "listen_port=8080", "--set", "flow_detail=0", "-s", "/addons/egress.py"]
