# senders — common tasks.
#
# The native crates build, test, lint and format under Bazel. The wasm frontend
# does not: it targets wasm32 and needs wasm-bindgen, wasm-opt and asset
# hashing on top of rustc, which trunk already does (see .bazelrc). So the few
# recipes that touch crates/web use trunk and cargo directly, and everything
# else goes through Bazel.
#
# Ordering matters in one place: the server pins the hash of trunk's inline
# bootstrap script into its Content-Security-Policy at startup, so the frontend
# must be built before the server runs or the page is blocked.

default:
    @just --list

# --- frontend (trunk) --------------------------------------------------------

# Build the wasm frontend into ./dist.
web:
    trunk build

# Build the wasm frontend, optimised.
web-release:
    trunk build --release

# --- native crates (bazel) ---------------------------------------------------

# Build just the server binary.
server:
    bazel build //crates/server:senders

# Everything, optimised.
build: web-release
    bazel build -c opt //crates/server:senders

# Lints and format checks are ordinary Bazel targets, so none of them
# discards another's analysis cache.

# Build, tests, clippy and rustfmt in one invocation.
test:
    bazel test //...

# Clippy on its own.
lint:
    bazel build //crates/proto:clippy //crates/server:clippy

# Format check on its own.
fmt-check:
    bazel test //crates/proto:rustfmt //crates/server:rustfmt

# rules_rust ships an apply tool for the targets it knows about; crates/web is
# outside the Bazel build, so cargo formats that one.

# Reformat in place.
fmt:
    bazel run @rules_rust//tools/rustfmt
    cd crates/web && cargo fmt --all

# --- frontend tests (cargo, wasm32) ------------------------------------------

# Needs wasm-bindgen-test-runner on PATH, at the same version as the
# wasm-bindgen dependency.

# Browser-crypto tests, under Node against the compiled wasm.
test-wasm:
    cd crates/web && cargo test --target wasm32-unknown-unknown

# Everything, both toolchains.
test-all: test test-wasm

# What CI should run.
ci: test-all

# --- running -----------------------------------------------------------------

# Absolute paths because `bazel run` executes from the runfiles tree, not from
# the workspace root.

# Run locally with no external dependencies: blobs on disk, metadata in memory.
dev: web
    bazel run //crates/server:senders -- \
        --bind 127.0.0.1:47920 \
        --storage fs:{{ justfile_directory() }}/data/blobs \
        --metadata memory: \
        --static-dir {{ justfile_directory() }}/dist

# Run against the containerised Dragonfly + Garage stack.
dev-stack: web
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose up -d dragonfly garage
    [ -f deploy/garage.env ] || ./scripts/init-garage.sh
    set -a; . ./deploy/garage.env; set +a
    export AWS_REGION=garage AWS_ENDPOINT_URL=http://127.0.0.1:47922 SENDERS_S3_PATH_STYLE=true
    bazel run //crates/server:senders -- \
        --bind 127.0.0.1:47920 \
        --storage s3://senders \
        --metadata redis://127.0.0.1:47921 \
        --static-dir "$PWD/dist"

# --- containers --------------------------------------------------------------

# -c opt matters: a fastbuild binary carries debug info and roughly doubles the
# image. Bazel packages ./dist, it does not produce it, hence web-release.

# Build the distroless image and load it into the local docker daemon.
image: web-release
    bazel run -c opt //deploy:image_load

# Bring the dependency containers up, with a one-time Garage setup.
stack-up:
    docker compose up -d dragonfly garage
    ./scripts/init-garage.sh

# Tear the dependency containers down, discarding their volumes.
stack-down:
    docker compose down -v
