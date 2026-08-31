//! The download page: `/d/{id}#{key}`.
//!
//! The id identifies the encrypted data; the part after the `#` is the key.
//! The server only ever sees the first half.

use crate::api;
use crate::crypto::{self, FileKeys};
use crate::i18n::{Lang, t, use_lang};
use crate::transfer;
use crate::ui::{ActivityLog, FileIcon, Logger, Progress, format_bytes};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params_map;
use senders_proto::{FileMetadata, FileParams, b64};

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Loading,
    /// The link alone is not enough; the recipient must supply the passphrase.
    NeedPassphrase {
        wrong: bool,
    },
    Ready,
    Working(f64),
    Saved,
    Failed(String),
}

/// Everything needed to decrypt, once access has been granted.
#[derive(Clone)]
struct Unlocked {
    keys: std::rc::Rc<FileKeys>,
    metadata: FileMetadata,
    nonce_prefix: Vec<u8>,
    cipher_len: u64,
    expires_at: u64,
    downloads_remaining: u32,
}

#[component]
#[expect(
    clippy::too_many_lines,
    reason = "a `view!` tree is one screen of markup; splitting it would scatter the page"
)]
pub fn DownloadPage() -> impl IntoView {
    let lang = use_lang();
    let params = use_params_map();
    let id = Signal::derive(move || params.get().get("id").unwrap_or_default());

    let phase = RwSignal::new(Phase::Loading);
    let unlocked = RwSignal::new_local(None::<Unlocked>);
    let file_params = RwSignal::new(None::<FileParams>);
    let passphrase = RwSignal::new(String::new());
    let log = Logger::new();

    // Held in a signal so the handlers capture only `Copy` values and can be
    // reused across several event bindings.
    let key = RwSignal::new(transfer::secret_from_fragment());

    // Resolve as much as possible on load: with no passphrase we can go
    // straight to showing the decrypted file name.
    Effect::new(move |_| {
        let id = id.get();
        if id.is_empty() {
            return;
        }
        let s = lang.strings();
        let Some(key) = key.get() else {
            log.bad(s.log_error, s.log_no_key);
            phase.set(Phase::Failed(s.link_incomplete.to_string()));
            return;
        };

        spawn_local(async move {
            log.info(s.log_checking, s.log_checking_text);
            let params = match api::params(&id).await {
                Ok(params) => params,
                Err(err) => {
                    log.bad(s.log_error, err.message.clone());
                    phase.set(Phase::Failed(if err.is_missing() {
                        s.gone.to_string()
                    } else {
                        err.message
                    }));
                    return;
                }
            };
            file_params.set(Some(params.clone()));

            if params.has_password {
                log.info(s.log_protected, s.log_protected_text);
                phase.set(Phase::NeedPassphrase { wrong: false });
                return;
            }

            log.info(s.log_keys, s.log_keys_text);
            match resolve(&id, &key, None, &params, lang, log).await {
                Ok(ready) => {
                    log.good(s.log_auth, lang.log_decrypted_name(&ready.metadata.name));
                    unlocked.set(Some(ready));
                    phase.set(Phase::Ready);
                }
                Err(message) => {
                    log.bad(s.log_error, message.clone());
                    phase.set(Phase::Failed(message));
                }
            }
        });
    });

    let unlock = move |(): ()| {
        let (Some(key), Some(params)) = (key.get(), file_params.get()) else {
            return;
        };
        let (id, entered) = (id.get(), passphrase.get());
        if entered.is_empty() {
            return;
        }
        phase.set(Phase::Working(0.0));
        spawn_local(async move {
            // `t()` is unavailable inside a spawned task; use the captured language.
            let s = lang.strings();
            log.info(s.passphrase, lang.log_stretching(params.kdf_iterations));
            match resolve(&id, &key, Some(&entered), &params, lang, log).await {
                Ok(ready) => {
                    log.good(s.log_auth, lang.log_decrypted_name(&ready.metadata.name));
                    unlocked.set(Some(ready));
                    phase.set(Phase::Ready);
                }
                Err(message) => {
                    log.bad(s.log_denied, message);
                    phase.set(Phase::NeedPassphrase { wrong: true });
                }
            }
        });
    };

    let start = move |_| {
        let Some(ready) = unlocked.get() else { return };
        let id = id.get();
        phase.set(Phase::Working(0.0));
        spawn_local(async move {
            let s = lang.strings();
            log.info(s.log_download, s.log_download_text);
            let result = transfer::open_file(
                &id,
                &ready.keys,
                &ready.nonce_prefix,
                ready.cipher_len,
                &ready.metadata.mime,
                move |done| phase.set(Phase::Working(done)),
            )
            .await;

            match result {
                Ok(blob) => match transfer::save_blob(&blob, &ready.metadata.name) {
                    Ok(()) => {
                        log.good(s.log_verified, s.log_verified_text);
                        phase.set(Phase::Saved);
                    }
                    Err(err) => {
                        log.bad(s.log_error, err.message.clone());
                        phase.set(Phase::Failed(err.message));
                    }
                },
                Err(err) => {
                    log.bad(s.log_error, err.message.clone());
                    phase.set(Phase::Failed(err.message));
                }
            }
        });
    };

    view! {
        <div class="single">
            <section class="panel reveal">
                <div class="panel__head">
                    <h2 class="panel__title">{move || t().incoming}</h2>
                </div>

                {move || match phase.get() {
                    Phase::Loading => view! { <p class="drop__hint">{t().loading}</p> }.into_any(),
                    Phase::Failed(message) => {
                        view! {
                            <p class="notice notice--bad">
                                <span>
                                    <strong>{t().unavailable}</strong>
                                    " "
                                    {message}
                                </span>
                            </p>
                        }
                            .into_any()
                    }
                    Phase::NeedPassphrase { wrong } => {
                        view! {
                            <div class="headline">
                                <p class="headline__name">{t().passphrase_required}</p>
                                <p class="headline__meta">{t().passphrase_required_hint}</p>
                            </div>
                            <label class="field">
                                <div class="field__label">
                                    <span>{t().passphrase}</span>
                                </div>
                                <input
                                    class="input input--mono"
                                    type="password"
                                    autocomplete="off"
                                    prop:value=move || passphrase.get()
                                    on:input=move |ev| passphrase.set(event_target_value(&ev))
                                    on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                                        if ev.key() == "Enter" {
                                            unlock(());
                                        }
                                    }
                                />
                            </label>
                            {wrong
                                .then(|| {
                                    view! {
                                        <p class="notice notice--bad">
                                            <span>
                                                <strong>{t().wrong_passphrase}</strong>
                                                " "
                                                {t().wrong_passphrase_body}
                                            </span>
                                        </p>
                                    }
                                })}
                            <button
                                class="btn"
                                disabled=move || passphrase.get().is_empty()
                                on:click=move |_| unlock(())
                            >
                                {t().unlock}
                            </button>
                        }
                            .into_any()
                    }
                    Phase::Working(done) => {
                        view! { <Progress label=t().decrypting value=Signal::derive(move || done) /> }
                            .into_any()
                    }
                    Phase::Saved => {
                        view! {
                            <div class="headline">
                                <p class="headline__name">{t().saved_title}</p>
                                <p class="headline__meta">{t().saved_body}</p>
                            </div>
                        }
                            .into_any()
                    }
                    Phase::Ready => ().into_any(),
                }}

                {move || {
                    unlocked
                        .get()
                        .filter(|_| !matches!(phase.get(), Phase::Saved))
                        .map(|ready| {
                            let name = ready.metadata.name.clone();
                            let size = ready.metadata.size;
                            let mime = ready.metadata.mime.clone();
                            let left = ready.downloads_remaining;
                            view! {
                                <div class="headline">
                                    <span class="headline__icon">
                                        <FileIcon size=26 />
                                    </span>
                                    <p class="headline__name">{name}</p>
                                    <p class="headline__meta">{format_bytes(crate::convert::to_f64(size))}</p>
                                </div>
                                <div class="rows">
                                    <div class="rows__row">
                                        <span class="rows__key">{t().type_label}</span>
                                        <span class="rows__val">{mime}</span>
                                    </div>
                                    <div class="rows__row">
                                        <span class="rows__key">{t().expires_in}</span>
                                        <span class="rows__val">{lang.until(ready.expires_at)}</span>
                                    </div>
                                    <div class="rows__row">
                                        <span class="rows__key">{t().downloads_left}</span>
                                        <span class="rows__val rows__val--accent">
                                            {lang.downloads(left)}
                                        </span>
                                    </div>
                                </div>
                                {(left <= 1)
                                    .then(|| {
                                        view! {
                                            <p class="notice notice--warn">
                                                <span>
                                                    <strong>{t().last_download_title}</strong>
                                                    " "
                                                    {t().last_download_body}
                                                </span>
                                            </p>
                                        }
                                    })}
                                <button
                                    class="btn"
                                    style:margin-top="1rem"
                                    disabled=move || matches!(phase.get(), Phase::Working(_))
                                    on:click=start
                                >
                                    {t().decrypt_and_save}
                                </button>
                            }
                        })
                }}

                <ActivityLog log=log />
            </section>
        </div>
    }
}

/// Derive keys, gain access, and decrypt the metadata blob.
///
/// A wrong passphrase fails at the metadata request with a 401, because the
/// passphrase *is* the access credential — the server refuses before any
/// encrypted data moves.
async fn resolve(
    id: &str,
    key: &[u8],
    passphrase: Option<&str>,
    params: &FileParams,
    lang: Lang,
    log: Logger,
) -> Result<Unlocked, String> {
    let mut keys = FileKeys::derive(key).await.map_err(|err| err.0)?;

    if let Some(passphrase) = passphrase {
        let salt = params
            .auth_salt
            .as_deref()
            .and_then(b64::decode)
            .ok_or_else(|| "the server did not supply a passphrase salt".to_string())?;
        let auth = crypto::pbkdf2(passphrase, &salt, params.kdf_iterations)
            .await
            .map_err(|err| err.0)?;
        keys = keys.with_auth(auth);
    }

    let metadata = api::metadata(id, &keys.auth).await.map_err(|err| {
        if err.is_unauthorized() {
            lang.strings().wrong_passphrase.to_string()
        } else {
            err.message
        }
    })?;
    log.info(lang.strings().log_auth, lang.strings().log_auth_text);

    let sealed = b64::decode(&metadata.metadata).ok_or_else(|| "malformed metadata".to_string())?;
    let plaintext = keys.open_metadata(&sealed).await.map_err(|err| err.0)?;
    let decoded: FileMetadata =
        serde_json::from_slice(&plaintext).map_err(|err| format!("malformed metadata: {err}"))?;
    let nonce_prefix =
        b64::decode(&metadata.nonce_prefix).ok_or_else(|| "malformed nonce".to_string())?;

    Ok(Unlocked {
        keys: std::rc::Rc::new(keys),
        metadata: decoded,
        nonce_prefix,
        cipher_len: metadata.size,
        expires_at: metadata.expires_at,
        downloads_remaining: metadata.downloads_remaining,
    })
}
