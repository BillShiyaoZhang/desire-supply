# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25

ARG PYTHON_IMAGE=python:3.14.1-slim-bookworm@sha256:5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff
ARG NODE_IMAGE=node:22.22.3-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752
ARG CADDY_IMAGE=caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.9.15@sha256:4c1ad814fe658851f50ff95ecd6948673fffddb0d7994bdb019dcb58227abd52
ARG POSTGRES_DEV_IMAGE=postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296

FROM ${PYTHON_IMAGE} AS platform-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY platform/pyproject.toml platform/uv.lock platform/README.md ./platform/
COPY platform/src ./platform/src
RUN python -m pip wheel --wheel-dir /build/wheels './platform[server]'

FROM ${PYTHON_IMAGE} AS platform-runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random
RUN groupadd --gid 10001 desire \
    && useradd --uid 10001 --gid desire --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin desire \
    && install -d -o root -g root -m 0555 \
        /opt/desire \
        /run/desire \
        /run/desire-tls \
        /run/identity-sources \
        /run/secrets \
    && install -d -o desire -g desire -m 0700 /run/identity-bootstrap
COPY --from=platform-builder /build/wheels /tmp/wheels
RUN python -m pip install --no-index --find-links=/tmp/wheels 'desire-supply-platform[server]' \
    && python -m pip check
WORKDIR /opt/desire
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "desire_platform.internal_pilot.api_server"]

FROM ${PYTHON_IMAGE} AS oidc-egress-guard-runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends nftables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0555 deploy/private-server-real-oidc-egress-guard.py /usr/local/bin/desire-real-oidc-egress-guard
USER 0:0
ENTRYPOINT ["/usr/local/bin/desire-real-oidc-egress-guard"]

FROM ${NODE_IMAGE} AS web-builder
ENV NODE_ENV=development \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler-build.log \
    MINIFLARE_REGISTRY_PATH=/tmp/miniflare-registry
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit
COPY web ./
RUN npm run build

FROM ${NODE_IMAGE} AS web-runtime
ENV NODE_ENV=production \
    WRANGLER_WRITE_LOGS=false \
    WRANGLER_LOG_PATH=/tmp/wrangler.log \
    MINIFLARE_REGISTRY_PATH=/tmp/miniflare-registry
WORKDIR /app/web
COPY --from=web-builder --chown=node:node /build/web /app/web
USER node
EXPOSE 3000
CMD ["./node_modules/.bin/vinext", "start", "--hostname", "0.0.0.0", "--port", "3000"]

FROM ${CADDY_IMAGE} AS edge-runtime-filesystem
RUN addgroup -S -g 10001 caddy \
    && adduser -S -D -H -u 10001 -G caddy caddy \
    && setcap -r /usr/bin/caddy \
    && mkdir -p /run/desire-tls /run/secrets \
    && chown caddy:caddy /run/desire-tls /run/secrets
COPY --chown=caddy:caddy deploy/Caddyfile /etc/caddy/Caddyfile

# Copying the prepared filesystem into scratch deliberately drops all inherited
# image configuration, including Caddy's extra EXPOSE entries.  Keep the
# runtime image configuration below as a closed, explicit allowlist.
FROM scratch AS edge-runtime
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    XDG_CONFIG_HOME=/tmp/caddy-config \
    XDG_DATA_HOME=/tmp/caddy-data
COPY --from=edge-runtime-filesystem / /
WORKDIR /srv
USER 10001:10001
EXPOSE 443 8080
CMD ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

FROM ${NODE_IMAGE} AS devcontainer-node
COPY --chmod=0555 deploy/devcontainer-runtime-closure.sh /tmp/desire-runtime-closure
RUN /tmp/desire-runtime-closure /node-runtime-packages.txt /usr/local /usr/local/bin/node

FROM ${PYTHON_IMAGE} AS devcontainer-python
# The slim image deliberately omits Tcl/Tk runtime libraries. Do not copy its
# unusable optional extension; close every explicitly selected Python ELF.
COPY --chmod=0555 deploy/devcontainer-runtime-closure.sh /tmp/desire-runtime-closure
RUN find /usr/local/lib -type f -path '*/lib-dynload/*_tkinter*.so' -delete \
    && /tmp/desire-runtime-closure /python-runtime-packages.txt /usr/local \
        /usr/local/bin/python3.14 \
        /usr/local/lib/libpython*.so* \
        /usr/local/lib/python*/lib-dynload/*.so
FROM ${UV_IMAGE} AS uv-binaries

FROM ${POSTGRES_DEV_IMAGE} AS devcontainer
ARG DEBIAN_FRONTEND=noninteractive
ENV HOME=/home/node \
    NPM_CONFIG_CACHE=/home/node/.npm \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/home/node/.cache/uv
COPY --from=devcontainer-python /python-runtime-packages.txt /tmp/python-runtime-packages.txt
COPY --from=devcontainer-node /node-runtime-packages.txt /tmp/node-runtime-packages.txt
RUN groupadd --gid 1000 node \
    && useradd --uid 1000 --gid node --create-home --home-dir /home/node --shell /bin/bash node \
    && apt-get update \
    && xargs -r apt-get install --yes --no-install-recommends < /tmp/python-runtime-packages.txt \
    && xargs -r apt-get install --yes --no-install-recommends < /tmp/node-runtime-packages.txt \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        git \
        netbase \
        openssh-client \
        sudo \
        tzdata \
    && apt-get clean \
    && rm -f /tmp/python-runtime-packages.txt /tmp/node-runtime-packages.txt \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' 'node ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/node \
    && chmod 0440 /etc/sudoers.d/node \
    && visudo -cf /etc/sudoers.d/node \
    && install -d -o node -g node -m 0755 \
        /home/node/.cache/uv \
        /home/node/.npm \
        /workspace \
        /workspace/platform \
        /workspace/platform/.venv \
        /workspace/mvp \
        /workspace/mvp/.venv \
        /workspace/web \
        /workspace/web/node_modules
COPY --from=devcontainer-node /usr/local/ /usr/local/
COPY --from=devcontainer-python /usr/local/ /usr/local/
COPY --from=uv-binaries /uv /uvx /usr/local/bin/
COPY --chmod=0555 --chown=node:node deploy/devcontainer-toolchain-check.sh /usr/local/bin/desire-devcontainer-toolchain-check
USER node
RUN test "$(id -u)" = "1000" \
    && /usr/local/bin/desire-devcontainer-toolchain-check
COPY --chmod=0755 --chown=node:node deploy/devcontainer-post-create.sh /usr/local/bin/desire-devcontainer-post-create
COPY --chmod=0755 --chown=node:node deploy/devcontainer-entrypoint.sh /usr/local/bin/desire-devcontainer-entrypoint
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/desire-devcontainer-entrypoint"]
CMD ["sleep", "infinity"]
