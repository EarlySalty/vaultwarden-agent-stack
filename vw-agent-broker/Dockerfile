# ---------------------------------------------------------------------------
# Broker-Image (multi-stage): baut das Rust-Binary und legt es in ein
# schlankes Debian-Runtime-Image. Kein OpenSSL noetig - reqwest nutzt rustls.
# ---------------------------------------------------------------------------
FROM rust:1-slim AS build

# gcc + libc-Header werden fuer rusqlite (bundled SQLite) gebraucht.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Erst nur das Manifest kopieren und die Abhaengigkeiten bauen - so bleibt
# dieser teure Layer im Cache, solange sich Cargo.toml nicht aendert.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

COPY src ./src
# mtime anfassen, damit cargo den echten Code auch wirklich neu uebersetzt
RUN touch src/main.rs && cargo build --release

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/broker broker

COPY --from=build /src/target/release/broker /usr/local/bin/broker

# /data haelt die SQLite-Datei (Tokens, Anfragen, Regeln, Audit).
RUN mkdir -p /data /etc/broker && chown -R broker:broker /data
VOLUME ["/data"]

USER broker
EXPOSE 8088

ENV BROKER_CONFIG=/etc/broker/config.toml \
    RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8088/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/broker"]
CMD ["serve"]
