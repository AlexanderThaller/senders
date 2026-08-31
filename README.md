# senders

End-to-end encrypted file sharing, in the spirit of the late Firefox Send.

You pick a file; your browser encrypts it and uploads only ciphertext; you get
a link. The server stores bytes it cannot read and deletes them once the link
expires or its downloads run out.

- **Server** — Rust, [axum]. Metadata in Redis (or in memory), blobs on disk or
  in any S3-compatible store.
- **Frontend** — Rust compiled to WebAssembly with [Leptos], using the
  browser's native WebCrypto for the actual AES and SHA work.
- **Deployment** — a single static binary plus a `dist/` directory. With Redis
  metadata and S3 blobs it keeps nothing on local disk, so it runs happily as
  stateless replicas.

---

## How the encryption works

A fresh 32-byte **key** is generated in the browser for every upload and placed
in the URL fragment — the part after the `#`. Browsers never send the fragment
to a server, so it stays out of request logs, proxy logs and `Referer`.

Three independent keys are derived from it with HKDF-SHA256 under distinct
labels:

| Derived key  | Label                  | Used for                                      |
|--------------|------------------------|-----------------------------------------------|
| content      | `senders/v1/content`   | AES-256-GCM over the file body                |
| metadata     | `senders/v1/metadata`  | AES-256-GCM over the file name, type and size |
| access       | `senders/v1/auth`      | the bearer capability proving you may download |

The body is encrypted with the **STREAM** construction: the plaintext is cut
into 64 KiB records, each sealed under the content key with the nonce

```
nonce = random_prefix(7) || record_counter_be32(4) || final_flag(1)
```

Distinct counters keep nonces unique, and the final-record flag means a
truncated file fails to authenticate instead of silently decrypting to a
prefix. Reordering, truncating or tampering with any record makes decryption
fail loudly rather than yield partial data.

The server stores only `SHA-256(access key)`, so a dump of the metadata store
does not let an attacker download anything.

### Passphrases and the second channel

Setting a passphrase replaces the link-derived access key with one derived by
PBKDF2-HMAC-SHA256 (250,000 rounds) over the passphrase and a random salt. The
link alone then no longer grants a download.

That is the point of the passphrase: **send the link and the passphrase over
different channels**. The result panel deliberately presents them as two
separate items with two separate copy buttons, so they do not end up pasted
into the same message. The **Generate** button produces a 100-bit passphrase in
Crockford base32 (no `I`, `L`, `O` or `U`), grouped for reading aloud:

```
NT80-CFH7-ECZF-XCVJ-4E1X
```

---

## What this does and does not protect against

**The server never receives the key.** It lives in the URL fragment, which
browsers do not transmit. You can verify this in any network inspector.

**But the server serves the code that holds the key.** A malicious or
compromised server could ship a modified bundle that reads `location.hash` and
sends it home. This is the fundamental limitation of *all* browser-delivered
end-to-end encryption — Firefox Send had it, and so do the web clients of every
"zero-knowledge" service. Encryption in a page you download from the server
each time is only as trustworthy as that server.

The honest mitigation is to **run it yourself**, so that the server is you.

What this build does to narrow the gap:

- A strict `Content-Security-Policy` with `connect-src 'self'` and
  `object-src 'none'`. The bundler emits one inline bootstrap script; rather
  than allowing `'unsafe-inline'`, the server hashes that script at startup and
  pins it in the policy. *(This means the server must be restarted after a
  frontend rebuild, or the page will be blocked.)*
- Subresource-integrity hashes on the JavaScript and WebAssembly, so if you
  trust the HTML you received, the rest is hash-locked.
- No third-party requests at all: fonts are self-hosted, there is no analytics
  and no CDN.
- `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.

Things worth knowing:

- Anyone who obtains the **whole link** can download the file, unless a
  passphrase is set. Treat it like a password: it lands in browser history,
  screen shares and chat backups.
- The server learns the ciphertext size, the upload and download times, and —
  when OIDC is enabled — which account uploaded what. It does not learn file
  names, types or contents.
- Files are held in memory while being encrypted or decrypted, spilling into
  browser-managed blobs. Very large files are limited by the browser, not the
  server.
- There is no forward secrecy and no sender authentication: a link proves
  someone had the key, not who.

---

## Quick start

Requires a Rust toolchain with the `wasm32-unknown-unknown` target, and
[trunk].

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk        # or use your distribution's package

just dev                   # builds the frontend, runs on 127.0.0.1:47920
```

That runs with files on local disk and metadata in memory — no external
services. Open <http://127.0.0.1:47920>.

> WebCrypto is only available in secure contexts. `localhost` counts; a bare IP
> address over plain HTTP does not. Put a TLS terminator in front for anything
> beyond your own machine.

### With real backends

`docker-compose.yml` brings up [Dragonfly] (Redis-compatible) for metadata and
[Garage] (S3-compatible) for blobs, on high ports so they do not collide with
anything you already run:

```sh
just stack-up              # starts both, creates the bucket and access key
just dev-stack             # runs senders against them
```

Or the whole thing in containers:

```sh
just image                 # builds the frontend, then the image, via Bazel
docker compose up -d       # serves on http://localhost:47920
```

There is no Dockerfile. The image is defined once, as `//deploy:image`, and
`just image` loads it into the local daemon as `senders:latest`; compose then
just runs it. See [Containers](#containers).

The compose stack publishes high ports (`47920` for senders, `47921` for
Dragonfly, `47922`/`47923` for Garage) so it does not collide with anything
already listening on `8080`, `6379` or `3900`.

---

## Configuration

Every setting is both a CLI flag and an environment variable.

| Variable | Default | Meaning |
|---|---|---|
| `SENDERS_BIND` | `0.0.0.0:8080` | listen address |
| `SENDERS_STORAGE` | `fs:./data/blobs` | `fs:<path>` or `s3://<bucket>[/<prefix>]` |
| `SENDERS_METADATA` | `memory:` | `redis://…`, `rediss://…`, or `memory:` |
| `SENDERS_STATIC_DIR` | `./dist` | built frontend |
| `SENDERS_MAX_FILE_SIZE` | `2147483648` | largest accepted upload, in bytes |
| `SENDERS_DEFAULT_EXPIRY` | `86400` | default lifetime, in seconds |
| `SENDERS_MAX_EXPIRY` | `2592000` | longest allowed lifetime (30 days is the hard ceiling) |
| `SENDERS_MAX_DOWNLOADS` | `1000` | largest allowed download budget |
| `SENDERS_REAP_INTERVAL` | `60` | seconds between expiry sweeps |
| `SENDERS_PUBLIC_URL` | `http://localhost:8080` | public origin, used for the OIDC redirect URI |
| `SENDERS_LOG` | `info,tower_http=warn` | `tracing` filter |

`senders --healthcheck` probes an already-running instance's `/healthz` and
exits 0 or 1 rather than serving. It exists so the distroless image can declare
a healthcheck without shipping a shell or an HTTP client.

Expiry is clamped to **1–30 days** and the download budget to **1–1000**. A
budget of `1` is the default: the file is destroyed as soon as it has been
downloaded once.

For S3, credentials come from the standard AWS environment
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`,
`AWS_ENDPOINT_URL`). Set `SENDERS_S3_PATH_STYLE=true` for MinIO, Garage and
other servers that do not do virtual-host-style addressing.

### Hiding the service behind OIDC

Rather than putting an `oauth2-proxy` container in front, the server speaks
OpenID Connect itself (authorization code flow with PKCE).

| Variable | Meaning |
|---|---|
| `SENDERS_AUTH_MODE` | `off`, `upload`, or `all` |
| `SENDERS_OIDC_ISSUER` | issuer URL; discovery uses `<issuer>/.well-known/openid-configuration` |
| `SENDERS_OIDC_CLIENT_ID` / `SENDERS_OIDC_CLIENT_SECRET` | client credentials |
| `SENDERS_OIDC_SCOPES` | extra scopes, comma-separated (default `email,profile`) |
| `SENDERS_OIDC_ALLOWED_DOMAINS` | optional email-domain allow-list |
| `SENDERS_SESSION_SECRET` | key for signing session cookies |
| `SENDERS_SESSION_TTL` | session lifetime in seconds (default 12 h) |
| `SENDERS_COOKIE_INSECURE` | drop the `Secure` cookie attribute, for plain-HTTP local testing |

- `upload` — signing in is required to upload, but share links stay publicly
  downloadable. This is usually what you want: colleagues sign in to send,
  recipients outside the company can still receive.
- `all` — every route requires a session, so the service is entirely hidden.
  Recipients need accounts too.

Register `<SENDERS_PUBLIC_URL>/auth/callback` as the redirect URI. Sessions are
stateless signed cookies, so set the same `SENDERS_SESSION_SECRET` on every
replica; without one, logins do not survive a restart. An allow-listed domain
is only honoured when the provider asserts `email_verified`.

---

## API

Everything the API handles is opaque to the server.

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/files` | session (in `upload`/`all` mode) | stream ciphertext in; returns id and owner token |
| `GET /api/files/{id}/params` | none | does this link need a passphrase, and with which salt |
| `GET /api/files/{id}/metadata` | access key | encrypted name/type blob and nonce prefix |
| `GET /api/files/{id}/blob` | access key | stream ciphertext out; consumes one download |
| `GET /api/files/{id}/owner` | owner token | download count and expiry |
| `PUT /api/files/{id}/password` | owner token | add, change or clear the passphrase |
| `DELETE /api/files/{id}` | owner token | delete immediately |
| `GET /api/info` | none | server limits and session state |
| `GET /healthz` | none | probes both stores |

Upload parameters travel as `x-senders-*` headers so the body can be streamed
straight into blob storage without buffering the whole file.

---

## Development

```sh
just test        # build, tests, clippy and rustfmt, in one Bazel invocation
just test-wasm   # browser-crypto tests, run under Node against the built wasm
just fmt         # reformat in place
just ci          # both of the above
```

The native crates go through Bazel; only the frontend recipes shell out to
trunk and cargo, because Bazel does not build it.

### Lints

The lint set lives in `[workspace.lints]` in `Cargo.toml` and is deliberately
strict: `missing_docs`, `missing_debug_implementations`, `unsafe_code =
"forbid"`, `clippy::pedantic`, `clippy::unwrap_used`, and
`clippy::wildcard_enum_match_arm` among others. `.clippy.toml` relaxes `unwrap`
and `dbg!` inside tests, where a panic *is* the failure report.

There is no second copy of that list for Bazel: `crate.from_cargo`'s
`generate_lint_config` reads it out of the manifest and `lint_config()` hands
it to every target, so `bazel build //crates/server:clippy` and
`cargo clippy` enforce the same thing.

Two consequences worth knowing:

- `unsafe_code` is forbidden, not merely denied, so it cannot be re-enabled
  locally by an attribute.
- `#[allow]` is itself linted (`clippy::allow_attributes`), and every exception
  needs a stated reason, so suppressions are written as
  `#[expect(lint, reason = "…")]`. There are a handful, each explaining why —
  mostly `f64` conversions at the JavaScript boundary, gathered in
  `crates/web/src/convert.rs`.

### Build profiles

`[profile.deploy]` in `Cargo.toml` is the shipping profile: LTO, one codegen
unit, `panic = "abort"`. `.cargo/config.toml` builds x86-64 targets for
`x86-64-v3`. Bazel has no notion of a named Cargo profile, so both are mirrored
in `.bazelrc` as `--config` shorthands:

```sh
cargo build --profile deploy
bazel build --config=deploy --config=x86-64-v3 //crates/server:senders
```

`--config=deploy` has to name the binary rather than `//...`: rustc requires a
single panic strategy across the crate graph and libtest needs unwinding, so
the test targets cannot build under it. `cargo test --profile deploy` fails the
same way.

The `x86-64-v3` flag is scoped to `cfg(target_arch = "x86_64")` rather than set
under `[build]`. A bare `[build] rustflags` also reaches `wasm32`, where rustc
ignores the unknown processor *and drops the target's default features with
it*, leaving wasm-bindgen unable to find `__wbindgen_externref_table_alloc`.

`just test-wasm` needs `wasm-bindgen-test-runner` on your `PATH` at the same
version as the `wasm-bindgen` dependency.

The wasm tests are the interesting ones: they exercise the real compiled
module, covering key separation, tamper detection, record reordering,
truncation, and byte-exact round trips at awkward chunk boundaries.

### Bazel

The native crates also build under Bazel. Clippy and rustfmt are ordinary
targets rather than separate invocations, so one `bazel test //...` covers
tests, lints and formatting without any run discarding another's analysis
cache:

```sh
bazel test //...                      # build + tests + clippy + rustfmt
bazel build //crates/server:senders   # just the binary
bazel build //crates/server:clippy    # lints on their own
bazel test //crates/server:rustfmt    # format check on its own
```

Dependencies and edition are read out of the Cargo manifests, so adding a crate
needs no `BUILD.bazel` change. `Cargo.lock` stays the source of truth for
versions; `MODULE.bazel.lock` records the resolved set and is committed.

The one thing that is restated is `crate_features` on the server targets:
rules_rust takes first-party feature flags explicitly, so the `s3` and `oidc`
defaults are named in `crates/server/BUILD.bazel`.

**Bazel does not build the frontend.** `crates/web` targets
`wasm32-unknown-unknown` and needs wasm-bindgen, wasm-opt and asset hashing on
top of rustc, all of which trunk already does. Run `trunk build --release`
before serving; there is no Bazel equivalent, and `crates/web` is listed in
`.bazelignore`.

### Continuous integration

Two workflows, both in `.github/workflows`:

- **Bazel** — `bazel test --lockfile_mode=error //...` covers build, tests,
  clippy and rustfmt in one invocation. `--lockfile_mode=error` means a stale
  committed `MODULE.bazel.lock` fails here instead of being silently
  regenerated. A second job covers `crates/web` with cargo, because Bazel does
  not build it and the browser cryptography would otherwise go untested and
  unlinted.
- **Docker** — builds `//deploy:image` and pushes it to GHCR, then signs it
  with cosign. Also runs weekly, so the distroless base picks up security
  updates even when nothing here changes. Pull requests build but do not push.

Both use `bazel-contrib/setup-bazel` for caching. The bazelisk, repository and
external caches are keyed independently of the workflow, so the expensive
parts — the Rust toolchain and the materialised external repos — are shared
between the two; only the per-workflow disk cache of action outputs is separate,
since one builds fastbuild and the other `--config=deploy`.

The published image is built **without** `--config=x86-64-v3`, unlike
`just image`. A local build can assume the machine it was built on; something
in a public registry cannot, and an x86-64-v3 binary dies with SIGILL on
anything older than Haswell.

```sh
docker pull ghcr.io/athaller/senders:latest
cosign verify ghcr.io/athaller/senders:latest \
  --certificate-identity-regexp 'https://github\.com/athaller/senders/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Localisation

The interface is available in English and German and follows the browser's
`navigator.languages`. There is no language picker — a share link should just
open in the reader's own language. Strings live in
`crates/web/src/i18n.rs`; adding a language means adding a `Strings` value and
a match arm.

---

## Containers

The image is built by Bazel with `rules_oci`, on
`gcr.io/distroless/cc-debian13`:

```sh
just image                             # frontend, then image, then load
bazel build --config=deploy //deploy:image       # the image on its own
bazel run  --config=deploy //deploy:image_load   # load it as senders:latest
```

The configuration matters: `--config=deploy --config=x86-64-v3` gives a 36 MB
image, plain `-c opt` 50 MB, and fastbuild 101 MB, because a fastbuild binary
carries debug info and skips LTO.

`just image` includes `--config=x86-64-v3`, so **the image requires an
x86-64-v3 host** — AVX2, BMI2 and FMA, meaning Haswell or Excavator and newer.
On anything older it dies with SIGILL. Drop that one `--config` for a portable
image.

Notes on the layout:

- **Distroless**, so there is no shell, no package manager and no curl in the
  image. It runs as `nonroot`.
- Because there is no curl, the container healthcheck is the binary itself:
  `senders --healthcheck` opens a connection to its own listen port, asks for
  `/healthz` and exits 0 or 1.
- **`cc`, not `base`** — the server links `libgcc_s`, which `base` does not
  carry.
- **`debian13`, not `debian12`.** rules_rs links against the build machine's C
  library, so the binary requires whatever glibc symbol versions that host
  provides — currently up to `GLIBC_2.38`. Trixie ships 2.41; bookworm only has
  2.36 and could not load it. This coupling is worth knowing about: building on
  a much newer host can still produce a binary the pinned base cannot run. A
  hermetic sysroot or a musl target would remove it, and neither is set up here.
- Two layers, binary and frontend, so a change to one does not push the other.
- Bazel packages `./dist`; it does not produce it. The `frontend` filegroup
  globs with `allow_empty = False`, so a forgotten `trunk build` is an error at
  analysis time rather than an image that silently serves nothing.

## Licence

MIT.

[axum]: https://github.com/tokio-rs/axum
[Leptos]: https://leptos.dev
[trunk]: https://trunkrs.dev
[Dragonfly]: https://www.dragonflydb.io
[Garage]: https://garagehq.deuxfleurs.fr
