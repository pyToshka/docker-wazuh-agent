############################
# Builder stage
############################
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-dev \
    gcc \
    build-essential \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt

# Build wheels for target architecture
RUN pip3 wheel \
    --no-cache-dir \
    --wheel-dir /tmp/wheels \
    -r /tmp/requirements.txt


############################
# Runtime stage
############################
FROM ubuntu:22.04

LABEL maintainer="support@opennix.ru"
LABEL description="Wazuh Docker Agent (Hardened Ubuntu)"

ENV DEBIAN_FRONTEND=noninteractive

ARG AGENT_VERSION="4.11.1-1"

ENV JOIN_MANAGER_MASTER_HOST=""
ENV JOIN_MANAGER_WORKER_HOST=""
ENV VIRUS_TOTAL_KEY=""
ENV JOIN_MANAGER_PROTOCOL="https"
ENV JOIN_MANAGER_USER=""
ENV JOIN_MANAGER_PASSWORD=""
ENV JOIN_MANAGER_API_PORT="55000"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 🔐 OS security upgrades + minimal packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      gnupg \
      inotify-tools \
      procps \
      python3 \
      python3-pip \
      python3-setuptools \
      python3-docker \
      openjdk-17-jre-headless \
 && rm -rf /var/lib/apt/lists/*

# Wazuh repo (secure keyring)
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=${AGENT_VERSION} && \
    rm -rf /var/lib/apt/lists/*

# App files
COPY *.py *.jinja2 /var/ossec/
WORKDIR /var/ossec/

# Python wheels from builder
COPY --from=builder /tmp/wheels /tmp/wheels

RUN pip3 install \
    --no-cache-dir \
    --no-index \
    /tmp/wheels/* && \
    chmod +x /var/ossec/register_agent.py && \
    chmod +x /var/ossec/deregister_agent.py && \
    rm -rf /tmp/* && \
    chown -R wazuh:wazuh /var/ossec/

# SCA policies
RUN mkdir -p /var/ossec/ruleset/sca
COPY sca/*.yml /var/ossec/ruleset/sca/
RUN chown -R root:wazuh /var/ossec/ruleset/sca && \
    chmod 750 /var/ossec/ruleset/sca && \
    chmod 640 /var/ossec/ruleset/sca/*.yml

EXPOSE 5000
ENTRYPOINT ["./register_agent.py"]
