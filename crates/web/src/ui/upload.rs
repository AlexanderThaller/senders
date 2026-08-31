//! The upload page: choose a file, decide how long it should live, encrypt it,
//! and hand back a link.

use crate::api::{self, UploadParams};
use crate::crypto;
use crate::i18n::{t, use_lang};
use crate::transfer;
use crate::ui::{ActivityLog, FileIcon, Logger, Progress, UploadIcon, format_bytes};
use leptos::prelude::*;
use leptos::task::spawn_local;
use senders_proto::{AUTH_SALT_LEN, PBKDF2_ITERATIONS, ServerInfo, b64};
use wasm_bindgen::JsCast;
use web_sys::{File, HtmlInputElement};

const EXPIRY_DAYS: [u64; 5] = [1, 3, 7, 14, 30];
const DOWNLOAD_LIMITS: [u32; 5] = [1, 2, 5, 20, 100];

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Idle,
    Encrypting(f64),
    Uploading(f64),
    Done,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
struct Share {
    url: String,
    id: String,
    owner_token: String,
    expires_at: u64,
    max_downloads: u32,
    passphrase: Option<String>,
}

#[component]
pub fn UploadPage(info: Signal<Option<ServerInfo>>) -> impl IntoView {
    let lang = use_lang();
    let file = RwSignal::new_local(None::<File>);
    let expiry_days = RwSignal::new(1u64);
    let max_downloads = RwSignal::new(1u32);
    let passphrase = RwSignal::new(String::new());
    let revealed = RwSignal::new(false);
    let phase = RwSignal::new(Phase::Idle);
    let share = RwSignal::new(None::<Share>);
    let dragging = RwSignal::new(false);
    let log = Logger::new();

    let busy =
        Signal::derive(move || matches!(phase.get(), Phase::Encrypting(_) | Phase::Uploading(_)));
    let size_limit = Signal::derive(move || info.get().map(|info| info.max_file_size));
    let oversized = Signal::derive(move || match (file.get(), size_limit.get()) {
        (Some(file), Some(limit)) => file.size() > limit as f64,
        _ => false,
    });

    let accept = move |picked: Option<File>| {
        if let Some(picked) = picked {
            log.clear();
            log.info(
                t().step_file,
                lang.log_file(&picked.name(), &format_bytes(picked.size())),
            );
            share.set(None);
            phase.set(Phase::Idle);
            file.set(Some(picked));
        }
    };

    let on_pick = move |ev: leptos::ev::Event| {
        let input: HtmlInputElement = ev
            .target()
            .expect("change events have a target")
            .unchecked_into();
        accept(input.files().and_then(|files| files.get(0)));
    };

    let on_drop = move |ev: leptos::ev::DragEvent| {
        ev.prevent_default();
        dragging.set(false);
        accept(
            ev.data_transfer()
                .and_then(|dt| dt.files())
                .and_then(|files| files.get(0)),
        );
    };

    let submit = move |_| {
        let Some(picked) = file.get() else { return };
        let secret_passphrase = passphrase.get();
        let expires_in = expiry_days.get() * 86_400;
        let downloads = max_downloads.get();

        spawn_local(async move {
            // `t()` reads a context that is not available inside a spawned
            // task, so resolve the strings from the captured language.
            let s = lang.strings();
            log.info(s.log_keys, s.log_keys_text);
            phase.set(Phase::Encrypting(0.0));

            let sealed =
                match transfer::seal_file(&picked, move |done| phase.set(Phase::Encrypting(done)))
                    .await
                {
                    Ok(sealed) => sealed,
                    Err(err) => {
                        log.bad(s.log_error, err.message.clone());
                        phase.set(Phase::Failed(err.message));
                        return;
                    }
                };
            log.good(s.log_encrypted, s.log_encrypted_text);

            // With a passphrase, the right to download comes from the
            // passphrase rather than from the link, so an intercepted link is
            // not enough on its own.
            let (auth_hash, auth_salt) = if secret_passphrase.is_empty() {
                match sealed.keys.auth_hash().await {
                    Ok(hash) => (b64::encode(hash), None),
                    Err(err) => {
                        log.bad(s.log_error, err.0.clone());
                        phase.set(Phase::Failed(err.0));
                        return;
                    }
                }
            } else {
                log.info(s.passphrase, lang.log_stretching(PBKDF2_ITERATIONS));
                let derived = async {
                    let salt = crypto::random_bytes(AUTH_SALT_LEN)?;
                    let auth = crypto::pbkdf2(&secret_passphrase, &salt, PBKDF2_ITERATIONS).await?;
                    Ok::<_, crypto::Error>((
                        b64::encode(crypto::sha256(&auth).await?),
                        Some(b64::encode(&salt)),
                    ))
                }
                .await;
                match derived {
                    Ok(pair) => pair,
                    Err(err) => {
                        log.bad(s.log_error, err.0.clone());
                        phase.set(Phase::Failed(err.0));
                        return;
                    }
                }
            };

            phase.set(Phase::Uploading(0.0));
            log.info(s.log_upload, s.log_upload_text);
            let params = UploadParams {
                metadata: sealed.metadata.clone(),
                auth_hash,
                nonce_prefix: b64::encode(&sealed.nonce_prefix),
                auth_salt,
                expires_in,
                max_downloads: downloads,
            };

            match api::upload(&sealed.blob, &params, move |done| {
                phase.set(Phase::Uploading(done))
            })
            .await
            {
                Ok(response) => {
                    let origin = web_sys::window()
                        .and_then(|window| window.location().origin().ok())
                        .unwrap_or_default();
                    log.good(s.log_done, lang.log_share_id(&response.id));
                    share.set(Some(Share {
                        url: transfer::share_url(&origin, &response.id, &sealed.secret),
                        id: response.id,
                        owner_token: response.owner_token,
                        expires_at: response.expires_at,
                        max_downloads: downloads,
                        passphrase: (!secret_passphrase.is_empty())
                            .then_some(secret_passphrase.clone()),
                    }));
                    phase.set(Phase::Done);
                }
                Err(err) => {
                    log.bad(s.log_error, err.message.clone());
                    phase.set(Phase::Failed(err.message));
                }
            }
        });
    };

    view! {
        <div class="grid">
            <section class="panel reveal">
                <div class="panel__head">
                    <h2 class="panel__title">{move || t().step_file}</h2>
                    <span class="panel__note">
                        {move || {
                            size_limit.get().map(|limit| lang.max_size(&format_bytes(limit as f64)))
                        }}
                    </span>
                </div>

                {move || match file.get() {
                    None => {
                        view! {
                            <label
                                class="drop"
                                class:drop--armed=move || dragging.get()
                                tabindex="0"
                                on:dragover=move |ev: leptos::ev::DragEvent| {
                                    ev.prevent_default();
                                    dragging.set(true);
                                }
                                on:dragleave=move |_| dragging.set(false)
                                on:drop=on_drop
                            >
                                <span class="drop__icon">
                                    <UploadIcon />
                                </span>
                                <span class="drop__prompt">{t().drop_prompt}</span>
                                <span class="drop__hint">{t().drop_hint}</span>
                                <input type="file" on:change=on_pick />
                            </label>
                        }
                            .into_any()
                    }
                    Some(picked) => {
                        let (name, size) = (picked.name(), picked.size());
                        view! {
                            <div class="filecard">
                                <span class="filecard__icon">
                                    <FileIcon />
                                </span>
                                <div>
                                    <p class="filecard__name">{name}</p>
                                    <p class="filecard__meta">{format_bytes(size)}</p>
                                </div>
                                <button
                                    class="btn btn--ghost btn--auto btn--small"
                                    disabled=move || busy.get()
                                    on:click=move |_| {
                                        file.set(None);
                                        share.set(None);
                                        log.clear();
                                        phase.set(Phase::Idle);
                                    }
                                >
                                    {t().replace}
                                </button>
                            </div>
                        }
                            .into_any()
                    }
                }}

                {move || match phase.get() {
                    Phase::Encrypting(done) => {
                        view! { <Progress label=t().encrypting value=Signal::derive(move || done) /> }
                            .into_any()
                    }
                    Phase::Uploading(done) => {
                        view! { <Progress label=t().uploading value=Signal::derive(move || done) /> }
                            .into_any()
                    }
                    Phase::Failed(message) => {
                        view! {
                            <p class="notice notice--bad">
                                <span>
                                    <strong>{t().failed}</strong>
                                    " "
                                    {message}
                                </span>
                            </p>
                        }
                            .into_any()
                    }
                    _ => ().into_any(),
                }}

                {move || {
                    oversized
                        .get()
                        .then(|| {
                            let limit = size_limit.get().map(|l| format_bytes(l as f64)).unwrap_or_default();
                            view! {
                                <p class="notice notice--bad">
                                    <span>
                                        <strong>{t().too_large}</strong>
                                        " "
                                        {lang.too_large_body(&limit)}
                                    </span>
                                </p>
                            }
                        })
                }}

                <ActivityLog log=log />
            </section>

            <section class="panel reveal">
                <div class="panel__head">
                    <h2 class="panel__title">{move || t().step_options}</h2>
                </div>

                <div class="field">
                    <div class="field__label">
                        <span>{move || t().expires_after}</span>
                        <span class="field__value">{move || lang.days(expiry_days.get())}</span>
                    </div>
                    <div class="choices" role="group" aria-label=t().expires_after>
                        {EXPIRY_DAYS
                            .iter()
                            .map(|days| {
                                let days = *days;
                                view! {
                                    <button
                                        type="button"
                                        class="choice"
                                        aria-pressed=move || (expiry_days.get() == days).to_string()
                                        on:click=move |_| expiry_days.set(days)
                                    >
                                        {days.to_string()}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                </div>

                <div class="field">
                    <div class="field__label">
                        <span>{move || t().download_limit}</span>
                        <span class="field__value">{move || lang.downloads(max_downloads.get())}</span>
                    </div>
                    <div class="choices" role="group" aria-label=t().download_limit>
                        {DOWNLOAD_LIMITS
                            .iter()
                            .map(|count| {
                                let count = *count;
                                view! {
                                    <button
                                        type="button"
                                        class="choice"
                                        aria-pressed=move || (max_downloads.get() == count).to_string()
                                        on:click=move |_| max_downloads.set(count)
                                    >
                                        {count.to_string()}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                </div>

                <div class="field">
                    <div class="field__label">
                        <span>{move || t().passphrase}</span>
                        <span class="field__value">{move || t().passphrase_optional}</span>
                    </div>
                    <div class="field__row">
                        <input
                            class="input"
                            class:input--mono=move || revealed.get()
                            type=move || if revealed.get() { "text" } else { "password" }
                            autocomplete="new-password"
                            placeholder=t().passphrase_placeholder
                            prop:value=move || passphrase.get()
                            on:input=move |ev| {
                                passphrase.set(event_target_value(&ev));
                                revealed.set(false);
                            }
                        />
                        <button
                            type="button"
                            class="btn btn--ghost btn--auto"
                            on:click=move |_| {
                                if let Ok(generated) = crypto::generate_passphrase() {
                                    passphrase.set(generated);
                                    revealed.set(true);
                                }
                            }
                        >
                            {t().generate}
                        </button>
                    </div>
                </div>

                <button
                    class="btn"
                    disabled=move || file.get().is_none() || busy.get() || oversized.get()
                    on:click=submit
                >
                    {move || if busy.get() { t().working } else { t().submit }}
                </button>

                <p class="notice">
                    <span>
                        <strong>{move || t().key_note_title}</strong>
                        " "
                        {move || t().key_note_body}
                    </span>
                </p>
            </section>
        </div>

        {move || share.get().map(|share| view! { <ShareResult share=share log=log /> })}
    }
}

/// One copyable value with its own label and its own delivery advice.
#[component]
fn Channel(label: String, value: String, hint: String) -> impl IntoView {
    let copied = RwSignal::new(false);
    let to_copy = value.clone();

    let copy = move |_| {
        let to_copy = to_copy.clone();
        spawn_local(async move {
            if let Some(clipboard) = web_sys::window().map(|window| window.navigator().clipboard())
            {
                let _ = wasm_bindgen_futures::JsFuture::from(clipboard.write_text(&to_copy)).await;
                copied.set(true);
            }
        });
    };

    view! {
        <div class="channel">
            <span class="channel__label">{label}</span>
            <div class="channel__row">
                <code class="channel__value">{value}</code>
                <button class="btn btn--ghost btn--auto" on:click=copy>
                    {move || if copied.get() { t().copied } else { t().copy }}
                </button>
            </div>
            <p class="channel__hint">{hint}</p>
        </div>
    }
}

/// The post-upload panel: what to send, where it goes, and the delete button.
#[component]
fn ShareResult(share: Share, log: Logger) -> impl IntoView {
    let lang = use_lang();
    let deleted = RwSignal::new(false);

    // Signals rather than captured `String`s, so the handler stays `Copy` and
    // can live inside a `Show` body.
    let id = RwSignal::new(share.id.clone());
    let owner_token = RwSignal::new(share.owner_token.clone());
    let delete = move |_| {
        let (id, owner_token) = (id.get(), owner_token.get());
        spawn_local(async move {
            let s = lang.strings();
            match api::delete(&id, &owner_token).await {
                Ok(()) => {
                    log.good(s.log_deleted, s.log_deleted_text);
                    deleted.set(true);
                }
                Err(err) => log.bad(s.log_error, err.message),
            }
        });
    };

    let Share {
        url,
        expires_at,
        max_downloads,
        passphrase,
        ..
    } = share;
    let protected = passphrase.is_some();

    view! {
        <section class="result reveal">
            <div class="result__head">
                <h2 class="result__title">
                    {move || if deleted.get() { t().deleted_title } else { t().ready_title }}
                </h2>
                <span class="result__sub">
                    {move || if deleted.get() { t().deleted_body } else { t().ready_body }}
                </span>
            </div>

            <div class="result__body">
                <Show when=move || !deleted.get()>
                    <Channel
                        label=t().link_label.to_string()
                        value=url.clone()
                        hint=t().link_hint.to_string()
                    />
                    {passphrase
                        .clone()
                        .map(|passphrase| {
                            view! {
                                <Channel
                                    label=t().passphrase_share_label.to_string()
                                    value=passphrase
                                    hint=t().passphrase_share_hint.to_string()
                                />
                            }
                        })}
                </Show>

                <dl class="facts">
                    <div>
                        <dt>{t().expires_in}</dt>
                        <dd>{lang.until(expires_at)}</dd>
                    </div>
                    <div>
                        <dt>{t().downloads_label}</dt>
                        <dd>{lang.downloads(max_downloads)}</dd>
                    </div>
                    <div>
                        <dt>{t().protection}</dt>
                        <dd>
                            {if protected { t().protection_passphrase } else { t().protection_none }}
                        </dd>
                    </div>
                </dl>

                <Show when=move || !deleted.get()>
                    <button class="btn btn--quiet btn--auto" on:click=delete>
                        {t().delete_now}
                    </button>
                    <p class="notice">
                        <span>
                            <strong>{t().owner_note_title}</strong>
                            " "
                            {t().owner_note_body}
                        </span>
                    </p>
                </Show>
            </div>
        </section>
    }
}
