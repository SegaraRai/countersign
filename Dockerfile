# syntax=docker/dockerfile:1

# Server image containing `countersignd` and the host-side `countersign` admin CLI.
# Client binaries (`countersign-sudo`, `countersign-ask`) are built separately for target hosts / CI.

# Stage 1: build the embedded SvelteKit web UI.
FROM node:26-slim AS web
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml stillwind.config.ts vite.config.ts ./
COPY web/package.json ./web/package.json
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY web ./web
RUN pnpm exec vp run build

# Stage 2: build countersignd and the countersign admin CLI.
FROM rust:1-trixie AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=web /src/web/build ./web/build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p countersignd -p countersign \
    && cp target/release/countersignd target/release/countersign /usr/local/bin/

# Stage 3: minimal runtime image.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/countersign --create-home --shell /usr/sbin/nologin countersign
COPY --from=rust /usr/local/bin/countersignd /usr/local/bin/countersignd
COPY --from=rust /usr/local/bin/countersign /usr/local/bin/countersign
USER countersign
WORKDIR /var/lib/countersign
VOLUME ["/var/lib/countersign"]
# Note: in containers, bind [server].listen to a reachable interface (e.g. 0.0.0.0:2780 with TLS
# or a container bridge IP behind a proxy). [server].metrics_listen (optional) is typically 127.0.0.1:2790.
EXPOSE 2780 2743
ENTRYPOINT ["/usr/local/bin/countersignd"]
CMD ["--config", "/etc/countersign/config.toml", "run"]
