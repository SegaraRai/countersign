# syntax=docker/dockerfile:1

# Stage 1: build the embedded SvelteKit web UI.
FROM node:26-slim AS web
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml stillwind.config.ts vite.config.ts ./
COPY web ./web
RUN pnpm install --frozen-lockfile && pnpm exec vp run build

# Stage 2: build countersignd and the countersign admin CLI.
FROM rust:1-trixie AS rust
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
COPY --from=web /src/web/build ./web/build
RUN cargo build --release -p countersignd -p countersign

# Stage 3: minimal runtime image.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/countersign --create-home --shell /usr/sbin/nologin countersign
COPY --from=rust /src/target/release/countersignd /usr/local/bin/countersignd
COPY --from=rust /src/target/release/countersign /usr/local/bin/countersign
USER countersign
WORKDIR /var/lib/countersign
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/countersignd"]
CMD ["--config", "/etc/countersign/config.toml", "run"]
