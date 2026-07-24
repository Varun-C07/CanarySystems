FROM python:3.11-slim

WORKDIR /agent

# Set HTTP proxy to route all outbound requests through Pillar A interceptor
ENV HTTP_PROXY=http://host.docker.internal:8080
ENV HTTPS_PROXY=http://host.docker.internal:8080
ENV NO_PROXY=localhost,127.0.0.1

# Create output directory for file/exec/package exfiltration channels
RUN mkdir -p /agent/output

COPY sandbox_agent/fake_agent.py /agent/fake_agent.py

CMD ["python3", "-u", "/agent/fake_agent.py"]