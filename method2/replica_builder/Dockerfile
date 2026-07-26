FROM python:3.11-slim

# Install Node.js 20 & essential networking/audit utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    git \
    gnupg \
    ca-certificates \
 && mkdir -p /etc/apt/keyrings \
 && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
 && apt-get update && apt-get install -y nodejs \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /agent

# Route all outbound HTTP/HTTPS traffic through Pillar A egress proxy
ENV HTTP_PROXY=http://host.docker.internal:8080
ENV HTTPS_PROXY=http://host.docker.internal:8080
ENV NO_PROXY=localhost,127.0.0.1

# Create workspace directories
RUN mkdir -p /agent/config /agent/watched /agent/chat_inbox /agent/output /agent/source

COPY sandbox_agent/fake_agent.py /agent/fake_agent.py
COPY sandbox_agent/entrypoint.py /agent/entrypoint.py

CMD ["python3", "-u", "/agent/entrypoint.py"]