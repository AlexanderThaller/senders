# Build the wasm frontend and the server, then ship a single small image.
FROM rust:1-bookworm AS builder

ARG TRUNK_VERSION=0.21.14
RUN rustup target add wasm32-unknown-unknown \
 && curl -sSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
    | tar -xzf - -C /usr/local/bin

WORKDIR /src
COPY . .

# The frontend must be built first: the server pins the hash of the bundler's
# inline bootstrap script in its Content-Security-Policy at startup.
RUN trunk build --release
RUN cargo build --release -p senders-server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin senders

COPY --from=builder /src/target/release/senders /usr/local/bin/senders
COPY --from=builder /src/dist /srv/dist

ENV SENDERS_STATIC_DIR=/srv/dist \
    SENDERS_BIND=0.0.0.0:8080 \
    SENDERS_LOG=info,tower_http=warn

EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/senders"]
