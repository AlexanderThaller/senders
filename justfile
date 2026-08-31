# senders — common tasks.
#
# The frontend must be built before the server starts: the server pins the
# hash of the bundler's inline bootstrap script into its CSP at startup, so a
# stale `dist` means a blank page.

set dotenv-load := false

wasm_bindgen_test := "wasm-bindgen-test-runner"

default:
    @just --list

# Build the wasm frontend into ./dist.
web:
    trunk build

web-release:
    trunk build --release

# Build the server.
server:
    cargo build -p senders-server

# Everything, release profile.
build: web-release
    cargo build --release -p senders-server

# Run locally with no external dependencies: files on disk, metadata in memory.
dev: web
    SENDERS_STORAGE=fs:./data/blobs \
    SENDERS_METADATA=memory: \
    SENDERS_STATIC_DIR=./dist \
    SENDERS_BIND=127.0.0.1:47920 \
    cargo run -p senders-server

# Run against the containerised Dragonfly + Garage stack.
dev-stack: web
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose up -d dragonfly garage
    [ -f deploy/garage.env ] || ./scripts/init-garage.sh
    set -a; . ./deploy/garage.env; set +a
    export AWS_REGION=garage AWS_ENDPOINT_URL=http://127.0.0.1:47922 SENDERS_S3_PATH_STYLE=true
    SENDERS_STORAGE=s3://senders \
    SENDERS_METADATA=redis://127.0.0.1:47921 \
    SENDERS_STATIC_DIR=./dist \
    SENDERS_BIND=127.0.0.1:47920 \
    cargo run -p senders-server

# Bring the local dependency containers up / down.
stack-up:
    docker compose up -d dragonfly garage
    ./scripts/init-garage.sh

stack-down:
    docker compose down -v

# Server and shared-crate tests.
test:
    cargo test --workspace

# Browser-crypto tests, run under Node against the compiled wasm.
test-wasm:
    cd crates/web && cargo test --target wasm32-unknown-unknown

# Everything.
test-all: test test-wasm

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cd crates/web && cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings

fmt:
    cargo fmt --all
    cd crates/web && cargo fmt --all

fmt-check:
    cargo fmt --all -- --check
    cd crates/web && cargo fmt --all -- --check

# What CI should run.
ci: fmt-check lint test-all

# The Bazel build covers the native crates only; the frontend stays with trunk.
bazel:
    bazel test //...

# -c opt matters: a fastbuild binary carries debug info and roughly doubles the
# image. Bazel packages ./dist, it does not produce it, hence web-release.

# Build the distroless image and load it into the local docker daemon.
image: web-release
    bazel run -c opt //deploy:image_load

bazel-clippy:
    bazel build //crates/server:clippy //crates/proto:clippy
