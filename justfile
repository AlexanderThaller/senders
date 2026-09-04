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

# Mirrors [profile.deploy] and .cargo/config.toml; see .bazelrc.
# Note --config=deploy cannot be applied to //... -- panic=abort and libtest
# are incompatible, exactly as `cargo test --profile deploy` is.

# Everything, built the way it ships.
build: web-release
    bazel build --config=deploy --config=x86-64-v3 //crates/server:senders

# --- native crates without bazel (cargo) -------------------------------------

# Bazel does not build everywhere -- there is no FreeBSD toolchain, for one --
# and underneath it the native crates are an ordinary Cargo workspace. These
# are the cargo equivalents of `server` and `build` above and produce the same
# binary, at target/deploy/senders rather than under bazel-bin.
#
# `--config=x86-64-v3` has no counterpart here: .cargo/config.toml already
# applies target-cpu=x86-64-v3 to every x86-64 build, so the binary carries the
# same requirement. What these do not give you is clippy and rustfmt, which
# Bazel runs as part of `just test`; `just ci` stays the check before a push.

# Build just the server binary, without Bazel.
server-cargo:
    cargo build --profile deploy --bin senders

# Everything, built the way it ships, without Bazel.
build-cargo: web-release server-cargo

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

# `just ci` runs exactly what the two workflows run, so a green local run is the
# only way to know a push will pass. The granular recipes above are for working;
# these are for checking.
#
# --lockfile_mode=error lives in ci-bazel and not in `test`: it fails on a stale
# MODULE.bazel.lock rather than regenerating it, which is what you want in CI
# and not what you want mid-change.

# Everything both CI workflows run.
ci: ci-bazel ci-wasm

# The Bazel workflow: build, tests, clippy and rustfmt.
ci-bazel:
    bazel test --lockfile_mode=error //...

# Bazel does not build crates/web, so its lints and format check have no Bazel
# target and have to run through cargo. Without this, `just ci` would pass while
# CI failed.

# The wasm job: frontend lints, format check and tests.
ci-wasm:
    cd crates/web && cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
    cd crates/web && cargo fmt --all -- --check
    cd crates/web && cargo test --target wasm32-unknown-unknown

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

# Built --config=deploy, matching [profile.deploy], plus --config=x86-64-v3.
# The resulting image therefore REQUIRES an x86-64-v3 host (AVX2, BMI2, FMA --
# Haswell/Excavator or newer) and will die with SIGILL on anything older. Drop
# the second --config for a portable image.
#
# Bazel packages ./dist, it does not produce it, hence web-release.

# Build the distroless image and load it into the local docker daemon.
image: web-release
    bazel run --config=deploy --config=x86-64-v3 //deploy:image_load

# Bring the dependency containers up, with a one-time Garage setup.
stack-up:
    docker compose up -d dragonfly garage
    ./scripts/init-garage.sh

# Tear the dependency containers down, discarding their volumes.
stack-down:
    docker compose down -v
