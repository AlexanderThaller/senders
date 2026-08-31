//! senders — browser client.
//!
//! Everything that matters cryptographically happens here: key generation, key
//! derivation, encryption and decryption. The server is a store for data it
//! cannot read, and this library is what makes that true.

pub mod api;
pub mod crypto;
pub mod i18n;
pub mod transfer;
pub mod ui;

use i18n::{Lang, t};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use senders_proto::ServerInfo;
use ui::{download::DownloadPage, format_bytes, upload::UploadPage};

/// Mount the application. Called by the thin `main` binary.
pub fn start() {
    console_error_panic_hook::set_once();
    // Drop the static boot placeholder now that the module is live.
    if let Some(boot) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("boot"))
    {
        boot.remove();
    }
    leptos::mount::mount_to_body(App);
}

#[component]
pub fn App() -> impl IntoView {
    // One detection for the whole tree, so nothing renders in two languages.
    let lang = Lang::detect();
    provide_context(lang);
    if let Some(element) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        let _ = element.set_attribute("lang", lang.tag());
    }

    let info = RwSignal::new(None::<ServerInfo>);
    spawn_local(async move {
        match api::server_info().await {
            Ok(fetched) => info.set(Some(fetched)),
            Err(err) => leptos::logging::warn!("could not read server info: {}", err.message),
        }
    });
    let info = Signal::derive(move || info.get());

    view! {
        <div class="shell">
            <Masthead info=info />
            <Router>
                <Routes fallback=|| view! { <Missing /> }>
                    <Route path=path!("/") view=move || view! { <UploadPage info=info /> } />
                    <Route path=path!("/d/:id") view=DownloadPage />
                </Routes>
            </Router>
            <Footer info=info />
        </div>
    }
}

#[component]
fn Masthead(info: Signal<Option<ServerInfo>>) -> impl IntoView {
    view! {
        <header class="masthead">
            <h1 class="wordmark">
                <a href="/">"senders"</a>
            </h1>
            <div class="masthead__meta">
                <span class="badge">
                    <span class="badge__dot"></span>
                    {move || t().encrypted_badge}
                </span>
                {move || {
                    info.get()
                        .map(|info| match info.session {
                            Some(session) => {
                                let who = session
                                    .name
                                    .or(session.email)
                                    .unwrap_or_else(|| session.subject.clone());
                                view! {
                                    <span>
                                        {who}
                                        " · "
                                        <a class="link" href="/auth/logout">
                                            {t().sign_out}
                                        </a>
                                    </span>
                                }
                                    .into_any()
                            }
                            None if info.auth_required => {
                                view! {
                                    <a class="link" href="/auth/login">
                                        {t().sign_in}
                                    </a>
                                }
                                    .into_any()
                            }
                            None => ().into_any(),
                        })
                }}
            </div>
        </header>
        <p class="tagline">
            {move || t().app_tagline_before}
            <strong>{move || t().app_tagline_strong}</strong>
            {move || t().app_tagline_after}
        </p>
    }
}

#[component]
fn Footer(info: Signal<Option<ServerInfo>>) -> impl IntoView {
    let lang = i18n::use_lang();
    view! {
        <footer class="footer">
            <span>
                {move || {
                    info.get()
                        .map(|info| {
                            lang.footer_limits(
                                &format_bytes(info.max_file_size as f64),
                                info.max_expiry_secs / 86_400,
                            )
                        })
                }}
            </span>
            <span>{move || t().footer_note}</span>
        </footer>
    }
}

#[component]
fn Missing() -> impl IntoView {
    view! {
        <div class="single">
            <section class="panel">
                <div class="panel__head">
                    <h2 class="panel__title">{move || t().not_found_title}</h2>
                </div>
                <p class="tagline">{move || t().not_found_body}</p>
                <a class="btn btn--ghost btn--auto" href="/">
                    {move || t().not_found_action}
                </a>
            </section>
        </div>
    }
}
