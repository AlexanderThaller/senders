//! Localisation. The language follows the browser's stated preference; there
//! is no picker, because a share link should just open in the reader's own
//! language.

use leptos::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    De,
}

impl Lang {
    /// Pick a language from an ordered list of BCP-47 tags, as
    /// `navigator.languages` supplies them. Unknown tags are skipped rather
    /// than aborting the search, so `["fr", "de"]` still yields German.
    pub fn from_tags<'a>(tags: impl IntoIterator<Item = &'a str>) -> Self {
        for tag in tags {
            match tag
                .split(['-', '_'])
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "de" => return Self::De,
                "en" => return Self::En,
                _ => continue,
            }
        }
        Self::En
    }

    /// Read the browser's preference.
    pub fn detect() -> Self {
        let Some(window) = web_sys::window() else {
            return Self::En;
        };
        let languages = window.navigator().languages();
        let tags: Vec<String> = languages
            .iter()
            .filter_map(|value| value.as_string())
            .collect();
        if tags.is_empty() {
            return window
                .navigator()
                .language()
                .map(|tag| Self::from_tags([tag.as_str()]))
                .unwrap_or(Self::En);
        }
        Self::from_tags(tags.iter().map(String::as_str))
    }

    /// The `lang` attribute value, so screen readers and hyphenation behave.
    pub fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }

    pub fn strings(self) -> &'static Strings {
        match self {
            Self::En => &EN,
            Self::De => &DE,
        }
    }

    pub fn days(self, count: u64) -> String {
        match (self, count) {
            (Self::En, 1) => "1 day".into(),
            (Self::En, n) => format!("{n} days"),
            (Self::De, 1) => "1 Tag".into(),
            (Self::De, n) => format!("{n} Tage"),
        }
    }

    pub fn downloads(self, count: u32) -> String {
        match (self, count) {
            (Self::En, 1) => "1 download".into(),
            (Self::En, n) => format!("{n} downloads"),
            (Self::De, 1) => "1 Download".into(),
            (Self::De, n) => format!("{n} Downloads"),
        }
    }

    /// A coarse "in 3 days" description of an absolute timestamp.
    pub fn until(self, expires_at: u64) -> String {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        if expires_at <= now {
            return match self {
                Self::En => "expired".into(),
                Self::De => "abgelaufen".into(),
            };
        }
        let seconds = expires_at - now;
        let (days, hours, minutes) = (
            seconds / 86_400,
            (seconds % 86_400) / 3_600,
            (seconds % 3_600) / 60,
        );
        match (self, days, hours) {
            (Self::En, 0, 0) => format!("{minutes} min"),
            (Self::En, 0, h) => format!("{h} h"),
            (Self::En, d, h) => format!("{d} d {h} h"),
            (Self::De, 0, 0) => format!("{minutes} Min."),
            (Self::De, 0, h) => format!("{h} Std."),
            (Self::De, d, h) => format!("{d} T. {h} Std."),
        }
    }

    pub fn max_size(self, size: &str) -> String {
        match self {
            Self::En => format!("up to {size}"),
            Self::De => format!("bis {size}"),
        }
    }

    pub fn too_large_body(self, size: &str) -> String {
        match self {
            Self::En => format!("This server does not accept files larger than {size}."),
            Self::De => format!("Dieser Server nimmt keine Dateien über {size} an."),
        }
    }

    pub fn footer_limits(self, size: &str, max_days: u64) -> String {
        match self {
            Self::En => format!("up to {size} · kept 1–{max_days} days"),
            Self::De => format!("bis {size} · Aufbewahrung 1–{max_days} Tage"),
        }
    }

    pub fn log_file(self, name: &str, size: &str) -> String {
        match self {
            Self::En => format!("{name} ({size}) selected"),
            Self::De => format!("{name} ({size}) ausgewählt"),
        }
    }

    pub fn log_share_id(self, id: &str) -> String {
        match self {
            Self::En => format!("share reference {id}"),
            Self::De => format!("Freigabe-Kennung {id}"),
        }
    }

    pub fn log_decrypted_name(self, name: &str) -> String {
        match self {
            Self::En => format!("file name decrypted: {name}"),
            Self::De => format!("Dateiname entschlüsselt: {name}"),
        }
    }

    pub fn log_stretching(self, iterations: u32) -> String {
        match self {
            Self::En => format!("stretching the passphrase over {iterations} rounds"),
            Self::De => format!("Passphrase wird über {iterations} Runden gestreckt"),
        }
    }
}

/// Every fixed string in the interface.
pub struct Strings {
    pub app_tagline_before: &'static str,
    pub app_tagline_strong: &'static str,
    pub app_tagline_after: &'static str,
    pub encrypted_badge: &'static str,
    pub sign_in: &'static str,
    pub sign_out: &'static str,
    pub footer_note: &'static str,

    pub step_file: &'static str,
    pub step_options: &'static str,
    pub drop_prompt: &'static str,
    pub drop_hint: &'static str,
    pub replace: &'static str,
    pub expires_after: &'static str,
    pub download_limit: &'static str,
    pub passphrase: &'static str,
    pub passphrase_optional: &'static str,
    pub passphrase_placeholder: &'static str,
    pub generate: &'static str,
    pub submit: &'static str,
    pub working: &'static str,
    pub encrypting: &'static str,
    pub uploading: &'static str,
    pub failed: &'static str,
    pub too_large: &'static str,
    pub key_note_title: &'static str,
    pub key_note_body: &'static str,
    pub activity: &'static str,

    pub ready_title: &'static str,
    pub ready_body: &'static str,
    pub deleted_title: &'static str,
    pub deleted_body: &'static str,
    pub link_label: &'static str,
    pub link_hint: &'static str,
    pub passphrase_share_label: &'static str,
    pub passphrase_share_hint: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub expires_in: &'static str,
    pub downloads_label: &'static str,
    pub protection: &'static str,
    pub protection_none: &'static str,
    pub protection_passphrase: &'static str,
    pub owner_note_title: &'static str,
    pub owner_note_body: &'static str,
    pub delete_now: &'static str,

    pub incoming: &'static str,
    pub loading: &'static str,
    pub unavailable: &'static str,
    pub gone: &'static str,
    pub link_incomplete: &'static str,
    pub passphrase_required: &'static str,
    pub passphrase_required_hint: &'static str,
    pub unlock: &'static str,
    pub wrong_passphrase: &'static str,
    pub wrong_passphrase_body: &'static str,
    pub decrypting: &'static str,
    pub saved_title: &'static str,
    pub saved_body: &'static str,
    pub type_label: &'static str,
    pub downloads_left: &'static str,
    pub last_download_title: &'static str,
    pub last_download_body: &'static str,
    pub decrypt_and_save: &'static str,

    pub not_found_title: &'static str,
    pub not_found_body: &'static str,
    pub not_found_action: &'static str,

    pub log_keys: &'static str,
    pub log_keys_text: &'static str,
    pub log_encrypted: &'static str,
    pub log_encrypted_text: &'static str,
    pub log_upload: &'static str,
    pub log_upload_text: &'static str,
    pub log_done: &'static str,
    pub log_error: &'static str,
    pub log_checking: &'static str,
    pub log_checking_text: &'static str,
    pub log_protected: &'static str,
    pub log_protected_text: &'static str,
    pub log_auth: &'static str,
    pub log_auth_text: &'static str,
    pub log_download: &'static str,
    pub log_download_text: &'static str,
    pub log_verified: &'static str,
    pub log_verified_text: &'static str,
    pub log_deleted: &'static str,
    pub log_deleted_text: &'static str,
    pub log_no_key: &'static str,
    pub log_denied: &'static str,
}

pub static EN: Strings = Strings {
    app_tagline_before: "Files are encrypted in your browser before they are uploaded. ",
    app_tagline_strong: "This server only ever stores data it cannot read",
    app_tagline_after: ", and deletes it once the link expires or its downloads run out.",
    encrypted_badge: "End-to-end encrypted",
    sign_in: "Sign in",
    sign_out: "Sign out",
    footer_note: "The key lives in the part of the link after the #, which browsers never send to a server.",

    step_file: "File",
    step_options: "Sharing options",
    drop_prompt: "Drop a file here",
    drop_hint: "or click to choose one",
    replace: "Replace",
    expires_after: "Expires after",
    download_limit: "Download limit",
    passphrase: "Passphrase",
    passphrase_optional: "optional",
    passphrase_placeholder: "leave empty to rely on the link alone",
    generate: "Generate",
    submit: "Encrypt and upload",
    working: "Working…",
    encrypting: "Encrypting",
    uploading: "Uploading",
    failed: "Something went wrong.",
    too_large: "That file is too large.",
    key_note_title: "The key never leaves this tab.",
    key_note_body: "Add a passphrase to split the secret across two channels, so an intercepted link is not enough on its own.",
    activity: "Activity",

    ready_title: "Ready to share",
    ready_body: "Send the whole link, including everything after the #.",
    deleted_title: "Deleted",
    deleted_body: "The link no longer works and nothing is left on the server.",
    link_label: "Link",
    link_hint: "Send this however you normally would.",
    passphrase_share_label: "Passphrase",
    passphrase_share_hint: "Send this a different way — another app, or say it out loud.",
    copy: "Copy",
    copied: "Copied",
    expires_in: "Expires in",
    downloads_label: "Downloads",
    protection: "Passphrase",
    protection_none: "none",
    protection_passphrase: "required",
    owner_note_title: "Keep this tab if you might want to delete the file.",
    owner_note_body: "The token that proves you own it is held in memory only and is gone after a reload.",
    delete_now: "Delete now",

    incoming: "Shared file",
    loading: "Checking the link…",
    unavailable: "Not available.",
    gone: "This link has expired, been used up, or was deleted by the person who shared it.",
    link_incomplete: "This link is incomplete. The part after the # is missing, and without it the file cannot be decrypted.",
    passphrase_required: "Passphrase required",
    passphrase_required_hint: "The sender protected this file with a passphrase and will have sent it to you separately.",
    unlock: "Unlock",
    wrong_passphrase: "That passphrase does not fit.",
    wrong_passphrase_body: "Nothing was downloaded. You can try again.",
    decrypting: "Decrypting",
    saved_title: "Saved",
    saved_body: "The file was decrypted and checked in your browser.",
    type_label: "Type",
    downloads_left: "Downloads left",
    last_download_title: "This is the last download.",
    last_download_body: "The server deletes the file as soon as you save it.",
    decrypt_and_save: "Decrypt and save",

    not_found_title: "Nothing here",
    not_found_body: "That address does not point at a shared file. A share link looks like /d/… with a key after the #.",
    not_found_action: "Share a file instead",

    log_keys: "keys",
    log_keys_text: "generated a new key and derived the encryption and access keys from it",
    log_encrypted: "encrypted",
    log_encrypted_text: "the file was encrypted in 64 KiB pieces; the key stayed in this tab",
    log_upload: "upload",
    log_upload_text: "sending the encrypted data to the server",
    log_done: "done",
    log_error: "error",
    log_checking: "checking",
    log_checking_text: "asking the server what this link needs",
    log_protected: "protected",
    log_protected_text: "this file needs a passphrase",
    log_auth: "access",
    log_auth_text: "the server accepted the access key",
    log_download: "download",
    log_download_text: "downloading and decrypting piece by piece",
    log_verified: "verified",
    log_verified_text: "every piece passed its integrity check",
    log_deleted: "deleted",
    log_deleted_text: "the file has been removed from the server",
    log_no_key: "this link has no key after the #",
    log_denied: "denied",
};

pub static DE: Strings = Strings {
    app_tagline_before: "Dateien werden in deinem Browser verschlüsselt, bevor sie hochgeladen werden. ",
    app_tagline_strong: "Dieser Server speichert nur Daten, die er nicht lesen kann",
    app_tagline_after: ", und löscht sie, sobald der Link abläuft oder die Downloads aufgebraucht sind.",
    encrypted_badge: "Ende-zu-Ende verschlüsselt",
    sign_in: "Anmelden",
    sign_out: "Abmelden",
    footer_note: "Der Schlüssel steht im Teil des Links nach dem #, den Browser nie an einen Server senden.",

    step_file: "Datei",
    step_options: "Freigabe-Optionen",
    drop_prompt: "Datei hierher ziehen",
    drop_hint: "oder klicken zum Auswählen",
    replace: "Ersetzen",
    expires_after: "Läuft ab nach",
    download_limit: "Download-Limit",
    passphrase: "Passphrase",
    passphrase_optional: "optional",
    passphrase_placeholder: "leer lassen, um nur den Link zu nutzen",
    generate: "Erzeugen",
    submit: "Verschlüsseln und hochladen",
    working: "Einen Moment…",
    encrypting: "Wird verschlüsselt",
    uploading: "Wird hochgeladen",
    failed: "Da ist etwas schiefgegangen.",
    too_large: "Diese Datei ist zu groß.",
    key_note_title: "Der Schlüssel verlässt diesen Tab nicht.",
    key_note_body: "Mit einer Passphrase verteilst du das Geheimnis auf zwei Kanäle — ein abgefangener Link allein reicht dann nicht.",
    activity: "Verlauf",

    ready_title: "Bereit zum Teilen",
    ready_body: "Sende den vollständigen Link, einschließlich allem nach dem #.",
    deleted_title: "Gelöscht",
    deleted_body: "Der Link funktioniert nicht mehr und auf dem Server ist nichts übrig.",
    link_label: "Link",
    link_hint: "Sende ihn so, wie du es normalerweise tust.",
    passphrase_share_label: "Passphrase",
    passphrase_share_hint: "Sende sie auf einem anderen Weg — eine andere App, oder sag sie am Telefon.",
    copy: "Kopieren",
    copied: "Kopiert",
    expires_in: "Läuft ab in",
    downloads_label: "Downloads",
    protection: "Passphrase",
    protection_none: "keine",
    protection_passphrase: "erforderlich",
    owner_note_title: "Lass diesen Tab offen, falls du die Datei löschen möchtest.",
    owner_note_body: "Der Nachweis, dass sie dir gehört, liegt nur im Arbeitsspeicher und ist nach einem Neuladen weg.",
    delete_now: "Jetzt löschen",

    incoming: "Geteilte Datei",
    loading: "Link wird geprüft…",
    unavailable: "Nicht verfügbar.",
    gone: "Dieser Link ist abgelaufen, aufgebraucht oder wurde von der teilenden Person gelöscht.",
    link_incomplete: "Dieser Link ist unvollständig. Der Teil nach dem # fehlt, und ohne ihn lässt sich die Datei nicht entschlüsseln.",
    passphrase_required: "Passphrase erforderlich",
    passphrase_required_hint: "Die Datei ist mit einer Passphrase geschützt; du hast sie separat erhalten.",
    unlock: "Entsperren",
    wrong_passphrase: "Diese Passphrase passt nicht.",
    wrong_passphrase_body: "Es wurde nichts heruntergeladen. Du kannst es erneut versuchen.",
    decrypting: "Wird entschlüsselt",
    saved_title: "Gespeichert",
    saved_body: "Die Datei wurde in deinem Browser entschlüsselt und geprüft.",
    type_label: "Typ",
    downloads_left: "Verbleibende Downloads",
    last_download_title: "Das ist der letzte Download.",
    last_download_body: "Der Server löscht die Datei, sobald du sie gespeichert hast.",
    decrypt_and_save: "Entschlüsseln und speichern",

    not_found_title: "Hier ist nichts",
    not_found_body: "Diese Adresse gehört zu keiner geteilten Datei. Ein Freigabe-Link sieht aus wie /d/… mit einem Schlüssel nach dem #.",
    not_found_action: "Stattdessen eine Datei teilen",

    log_keys: "Schlüssel",
    log_keys_text: "neuer Schlüssel erzeugt und daraus Verschlüsselungs- und Zugriffsschlüssel abgeleitet",
    log_encrypted: "verschlüsselt",
    log_encrypted_text: "Datei in 64-KiB-Stücken verschlüsselt; der Schlüssel blieb in diesem Tab",
    log_upload: "Upload",
    log_upload_text: "verschlüsselte Daten werden an den Server gesendet",
    log_done: "fertig",
    log_error: "Fehler",
    log_checking: "Prüfung",
    log_checking_text: "Server wird gefragt, was dieser Link benötigt",
    log_protected: "geschützt",
    log_protected_text: "diese Datei benötigt eine Passphrase",
    log_auth: "Zugriff",
    log_auth_text: "der Server hat den Zugriffsschlüssel akzeptiert",
    log_download: "Download",
    log_download_text: "wird Stück für Stück geladen und entschlüsselt",
    log_verified: "geprüft",
    log_verified_text: "jedes Stück hat seine Integritätsprüfung bestanden",
    log_deleted: "gelöscht",
    log_deleted_text: "die Datei wurde vom Server entfernt",
    log_no_key: "dieser Link enthält keinen Schlüssel nach dem #",
    log_denied: "abgelehnt",
};

/// Read the active language from context. Every component uses this rather
/// than re-detecting, so the whole tree renders one language.
pub fn use_lang() -> Lang {
    use_context::<Lang>().unwrap_or(Lang::En)
}

/// Shorthand for the active string table.
pub fn t() -> &'static Strings {
    use_lang().strings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_tags_are_matched_by_primary_subtag() {
        assert_eq!(Lang::from_tags(["de-DE", "en-US"]), Lang::De);
        assert_eq!(Lang::from_tags(["de_AT"]), Lang::De);
        assert_eq!(Lang::from_tags(["DE"]), Lang::De);
        assert_eq!(Lang::from_tags(["en-GB", "de"]), Lang::En);
        // An unsupported first choice must not stop the search.
        assert_eq!(Lang::from_tags(["fr-FR", "de-CH"]), Lang::De);
        // "german" is not a tag; "de" is. Do not match on a prefix.
        assert_eq!(Lang::from_tags(["deutsch"]), Lang::En);
        assert_eq!(Lang::from_tags([]), Lang::En);
    }

    #[test]
    fn plurals_agree_in_both_languages() {
        assert_eq!(Lang::En.days(1), "1 day");
        assert_eq!(Lang::En.days(30), "30 days");
        assert_eq!(Lang::De.days(1), "1 Tag");
        assert_eq!(Lang::De.days(30), "30 Tage");
        assert_eq!(Lang::En.downloads(1), "1 download");
        assert_eq!(Lang::De.downloads(5), "5 Downloads");
    }
}
