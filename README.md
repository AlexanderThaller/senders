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
docker compose up -d --build     # serves on http://localhost:47920
```

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
just test        # server and shared-crate tests
just test-wasm   # browser-crypto tests, run under Node against the built wasm
just lint        # clippy, warnings denied
just ci          # formatting, lint and every test
```

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

### Localisation

The interface is available in English and German and follows the browser's
`navigator.languages`. There is no language picker — a share link should just
open in the reader's own language. Strings live in
`crates/web/src/i18n.rs`; adding a language means adding a `Strings` value and
a match arm.

---

## Licence

MIT.

[axum]: https://github.com/tokio-rs/axum
[Leptos]: https://leptos.dev
[trunk]: https://trunkrs.dev
[Dragonfly]: https://www.dragonflydb.io
[Garage]: https://garagehq.deuxfleurs.fr
