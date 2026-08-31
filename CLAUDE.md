# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Shape of the repo

Two Cargo workspaces, deliberately separate:

* the root one (`crates/proto`, `crates/server`) — native, built and tested by
  Bazel;
* `crates/web` — the Leptos frontend, `wasm32-unknown-unknown`, built by trunk.
  It is listed in `.bazelignore`; **Bazel does not build it**, so
  `bazel test //...` covers none of it. Its lint table is a copy, because a
  separate workspace cannot inherit `[workspace.lints]`.

## Verification

Run this before committing. It is exactly what the two workflows run, so a green
local run is the only way to know the push will pass:

```sh
just ci
```

While working, the halves are `just test` (Bazel: build, tests, clippy and
rustfmt in one invocation) and `just test-wasm` (the frontend, under Node
against the compiled wasm). `just ci` additionally lints and format-checks
`crates/web`, which has no Bazel target — that is the half easiest to forget.

Notes:

* Clippy runs with `-D warnings`. Fix the cause; reach for
  `#[expect(..., reason = "...")]` only when the lint is genuinely wrong, never
  `#[allow]` — `clippy::allow_attributes` rejects it anyway.
* The lint set lives in `[workspace.lints]` in `Cargo.toml` and nowhere else.
  Bazel reads it from the manifest through `generate_lint_config`, so there is
  no second copy to keep in step.
* `just test-wasm` needs `wasm-bindgen-test-runner` on `PATH` at exactly the
  version in `crates/web/Cargo.lock`. A mismatch fails obscurely with
  `failed to find the __wbindgen_externref_table_alloc function`.

## Build order

The server hashes trunk's inline bootstrap script at **startup** and pins it in
its `Content-Security-Policy`. So:

* build the frontend before running the server, and
* **restart the server after every frontend rebuild**, or the page is blocked
  and comes up blank.

`just dev`, `just dev-stack` and `just image` all depend on the frontend recipe
already. A bare `bazel build //deploy:image` does not — `//deploy:frontend_guard`
will tell you so.

## Bazel

* Everything under `//deploy` that needs `./dist` is tagged `manual` and is
  skipped by `//...`. Build the image by label, or with `just image`.
* The `dist/**` glob uses `allow_empty = True` and must keep doing so: globs are
  evaluated at package *load* time, so `False` breaks every `bazel … //...` on a
  tree where trunk has not run, rather than only the image build.
* `--config=deploy` mirrors `[profile.deploy]`. It cannot be applied to `//...`:
  `panic=abort` and libtest are incompatible, exactly as
  `cargo test --profile deploy` is. Name the binary.
* `.cargo/config.toml` scopes `target-cpu=x86-64-v3` to
  `cfg(target_arch = "x86_64")`. Do not move it back under `[build]`: rustc
  ignores the unknown processor on wasm32 *and drops the target's default
  features with it*, which breaks wasm-bindgen.

## Local stack

`just stack-up` runs Dragonfly and Garage; `just dev-stack` points the server at
them. High ports so they do not collide with anything: 47920 senders, 47921
Dragonfly, 47922 Garage S3, 47923 Garage admin. `deploy/garage.env` is generated
and gitignored — it holds credentials, do not commit it.

## The part that is easy to break

The server is meant to be unable to read what it stores. Keep it that way:

* Key material must never reach the server, a log line, or a `Debug` impl.
  Several types have hand-written `Debug` impls that redact; do not replace them
  with derives.
* `senders-proto`'s `INFO_*` labels, `CHUNK_SIZE`, and the STREAM nonce layout
  are wire format. Changing any of them silently breaks every link already
  shared — they are not internal constants.
* The frontend is the only thing that sees plaintext. Anything moved from
  `crates/web` into the server is a change to the threat model, not a
  refactor.

`README.md` sets out the protocol and is explicit about what this design does
*not* protect against; read it before changing anything cryptographic.

## Commits

Conventional Commits. Explain *why* in the body — the surprising constraints in
this repo are mostly recorded there and in the comments, not in the code.
