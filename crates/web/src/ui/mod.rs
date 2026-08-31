//! Shared UI pieces: the activity list, the progress bar, and small helpers.

pub mod download;
pub mod upload;

use crate::i18n::t;
use leptos::prelude::*;

/// One line in the activity list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub tag: String,
    pub text: String,
    pub kind: LogKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogKind {
    Info,
    Good,
    Bad,
}

/// A cheap handle to the activity list so any async step can narrate itself.
///
/// This is not decoration: "end-to-end encrypted" is a claim a user cannot
/// check, and showing the steps as they happen is the closest the interface
/// can get to letting them watch.
#[derive(Clone, Copy)]
pub struct Logger(pub RwSignal<Vec<LogEntry>>);

impl Logger {
    pub fn new() -> Self {
        Self(RwSignal::new(Vec::new()))
    }

    fn push(&self, kind: LogKind, tag: &str, text: impl Into<String>) {
        self.0.update(|entries| {
            entries.push(LogEntry {
                tag: tag.to_string(),
                text: text.into(),
                kind,
            });
        });
    }

    pub fn info(&self, tag: &str, text: impl Into<String>) {
        self.push(LogKind::Info, tag, text);
    }

    pub fn good(&self, tag: &str, text: impl Into<String>) {
        self.push(LogKind::Good, tag, text);
    }

    pub fn bad(&self, tag: &str, text: impl Into<String>) {
        self.push(LogKind::Bad, tag, text);
    }

    pub fn clear(&self) {
        self.0.update(Vec::clear);
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

#[component]
pub fn ActivityLog(log: Logger) -> impl IntoView {
    view! {
        <div class="log" class:log--empty=move || log.0.read().is_empty()>
            <p class="log__title">{move || t().activity}</p>
            <ul class="log__list" role="log" aria-live="polite">
                {move || {
                    log.0
                        .get()
                        .into_iter()
                        .map(|entry| {
                            let row_class = match entry.kind {
                                LogKind::Info => "log__row",
                                LogKind::Good => "log__row log__row--flare",
                                LogKind::Bad => "log__row log__row--bad",
                            };
                            view! {
                                <li class=row_class>
                                    <span class="log__tag">{entry.tag}</span>
                                    <span class="log__text">{entry.text}</span>
                                </li>
                            }
                        })
                        .collect_view()
                }}
            </ul>
        </div>
    }
}

#[component]
pub fn Progress(#[prop(into)] label: Signal<String>, value: Signal<f64>) -> impl IntoView {
    view! {
        <div class="progress">
            <div class="progress__head">
                <span>{move || label.get()}</span>
                <span>{move || format!("{:.0}%", value.get() * 100.0)}</span>
            </div>
            <div
                class="progress__track"
                role="progressbar"
                aria-valuemin="0"
                aria-valuemax="100"
                aria-valuenow=move || format!("{:.0}", value.get() * 100.0)
            >
                <div
                    class="progress__fill"
                    style:width=move || format!("{:.2}%", value.get().clamp(0.0, 1.0) * 100.0)
                ></div>
            </div>
        </div>
    }
}

/// Human-readable byte counts. Binary units are the same in both languages.
pub fn format_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A document icon, for the selected-file card and the download headline.
#[component]
pub fn FileIcon(#[prop(default = 20)] size: u32) -> impl IntoView {
    view! {
        <svg
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.6"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            <path d="M14 3v5h5" />
            <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
        </svg>
    }
}

/// An upload arrow, used in the empty drop zone.
#[component]
pub fn UploadIcon(#[prop(default = 26)] size: u32) -> impl IntoView {
    view! {
        <svg
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.6"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
        >
            <path d="M12 16V4" />
            <path d="m7 9 5-5 5 5" />
            <path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
        </svg>
    }
}
