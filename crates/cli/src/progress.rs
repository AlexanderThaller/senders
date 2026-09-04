//! Byte-counting progress bars for `upload` and `download`.
//!
//! Deliberately a wrapper around the ciphertext *stream* rather than a hook
//! inside `transfer.rs`: what a user waits for is the network, and counting
//! the chunks that cross it keeps the record loop — the part that must stay
//! easy to audit — free of display concerns. The totals are therefore
//! ciphertext lengths, a per-64 KiB-record tag larger than the file itself.
//!
//! Bars are drawn on stderr, so the share link on stdout stays pipeable.

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt as _};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Bar layout: a fixed-width label so upload and download line up, then the
/// bar, the byte counts, the rate and an estimate.
const TEMPLATE: &str = "{msg:<11} [{bar:28}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})";

/// Whether a command draws progress bars.
///
/// `Auto` still draws nothing when stderr is not a terminal — indicatif
/// suppresses it — so redirected output needs no flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Draw a bar when stderr is a terminal.
    Auto,
    /// Never draw one.
    Off,
}

impl Mode {
    /// A bar counting up to `total` bytes, labelled `message`.
    ///
    /// `Off` only swaps the draw target: the counting is identical either
    /// way, so nothing downstream has to care which one it got.
    #[must_use]
    pub fn bar(self, total: u64, message: &'static str) -> Progress {
        let bar = ProgressBar::new(total);
        match self {
            Self::Off => bar.set_draw_target(ProgressDrawTarget::hidden()),
            Self::Auto => {}
        }
        bar.set_style(
            ProgressStyle::with_template(TEMPLATE)
                .expect("the template is a constant and parses")
                .progress_chars("=> "),
        );
        bar.set_message(message);
        // Without a steady tick the elapsed time and rate freeze whenever the
        // transfer stalls, which is exactly when they are worth watching.
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        Progress(bar)
    }
}

/// A running progress bar, or a stand-in that draws nothing.
#[derive(Debug, Clone)]
pub struct Progress(ProgressBar);

impl Progress {
    /// Wrap `stream`, advancing the bar by the size of every chunk that
    /// passes through. Errors pass through untouched.
    ///
    /// `use<S, E>` keeps `&self` out of the returned type: the sealed upload
    /// body has to be `'static` to become a `reqwest::Body`.
    pub fn track<S, E>(&self, stream: S) -> impl Stream<Item = Result<Bytes, E>> + use<S, E>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        let bar = self.0.clone();
        stream.inspect_ok(move |chunk| bar.inc(chunk.len() as u64))
    }

    /// Stop the bar and leave it on screen, so the elapsed time and average
    /// rate survive the lines printed after it.
    ///
    /// A completed transfer snaps to 100%; a failed one stays where it
    /// stopped rather than claiming bytes that never arrived, so the bar
    /// above an error message agrees with it.
    ///
    /// A drawn bar leaves the cursor at the end of its own line — that is how
    /// it redraws in place — so the newline it never wrote has to be written
    /// here, or the next line lands on top of it.
    pub fn close<T, E>(&self, outcome: &Result<T, E>) {
        if outcome.is_ok() {
            self.0.finish();
        } else {
            self.0.abandon();
        }
        if !self.0.is_hidden() {
            eprintln!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Mode::Off` keeps counting, it only stops drawing, which is what makes
    /// it usable as the stand-in in these tests.
    #[tokio::test]
    async fn tracking_counts_every_chunk_that_passes_through() {
        let progress = Mode::Off.bar(6, "Testing");
        let chunks: Vec<Result<Bytes, ()>> = vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"de")),
            Ok(Bytes::from_static(b"f")),
        ];

        let collected: Vec<Bytes> = progress
            .track(futures_util::stream::iter(chunks))
            .try_collect()
            .await
            .expect("no errors in the stream");

        assert_eq!(collected.len(), 3, "chunks must pass through unchanged");
        assert_eq!(progress.0.position(), 6);
    }

    #[tokio::test]
    async fn a_failed_transfer_is_not_rounded_up_to_the_total() {
        let progress = Mode::Off.bar(100, "Testing");
        let chunks: Vec<Result<Bytes, &str>> =
            vec![Ok(Bytes::from_static(b"abc")), Err("connection reset")];

        let outcome: Result<Vec<Bytes>, &str> = progress
            .track(futures_util::stream::iter(chunks))
            .try_collect()
            .await;
        progress.close(&outcome);

        assert!(outcome.is_err());
        assert_eq!(
            progress.0.position(),
            3,
            "an abandoned bar reports the bytes that actually arrived"
        );
    }

    #[tokio::test]
    async fn a_completed_transfer_closes_at_the_total() {
        let progress = Mode::Off.bar(100, "Testing");
        progress.close::<(), ()>(&Ok(()));
        assert_eq!(progress.0.position(), 100);
    }
}
