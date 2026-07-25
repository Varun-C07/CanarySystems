FROM python:3.11-slim

WORKDIR /agent

# Set HTTP proxy to route all outbound requests through Pillar A interceptor.
# This means fake_agent.py's own webhook POST to the port-9000 listener
# (listener.py) is ALSO routed through here first, not sent to it directly --
# the interceptor forwards exactly that one destination back to the real
# listener over loopback so canary_hits.json still gets populated, while
# every other (genuinely external) destination stays intercepted-only.
# See egress_interceptor.py's LISTENER_FORWARD_HOST/PORT and module docstring.
ENV HTTP_PROXY=http://host.docker.internal:8080
ENV HTTPS_PROXY=http://host.docker.internal:8080
ENV NO_PROXY=localhost,127.0.0.1

# Create output directory for file/exec/package exfiltration channels
RUN mkdir -p /agent/output

COPY sandbox_agent/fake_agent.py /agent/fake_agent.py

CMD ["python3", "-u", "/agent/fake_agent.py"]