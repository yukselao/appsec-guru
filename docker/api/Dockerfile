# syntax=docker/dockerfile:1
# Shared runtime for the Python services (migrate, api). Only dependencies are
# installed here; application code is bind-mounted at runtime.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 tini openssh-client sshpass git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# ffuf for the Hidden Path Discovery feature.
ARG FFUF_VERSION=2.1.0
RUN set -eux; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=amd64;; arm64) a=arm64;; *) a=amd64;; esac; \
    curl -fsSL -o /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${a}.tar.gz"; \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf; rm /tmp/ffuf.tar.gz; chmod 755 /usr/local/bin/ffuf

RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt \
    pip install --no-cache-dir -r /tmp/requirements.txt

RUN useradd --uid 1000 --create-home app \
    && mkdir -p /var/log/was-troubleshooter/runs /var/lib/was-troubleshooter/sast /var/lib/was-troubleshooter/wordlists /home/app/.ssh \
    && chown -R app:app /var/log/was-troubleshooter /var/lib/was-troubleshooter /home/app/.ssh \
    && chmod 700 /home/app/.ssh

COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER app
WORKDIR /app
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
