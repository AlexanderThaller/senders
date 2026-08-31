//! Numeric conversions across the JavaScript boundary.
//!
//! Everything JavaScript hands us — file sizes, byte offsets, timestamps — is
//! an `f64`, and everything handed back for display has to become one again.
//! These conversions are lossy in principle and exact in practice: `f64`
//! represents every integer below 2^53, which is eight petabytes of file, or
//! 285 million years of Unix timestamp.
//!
//! Keeping them here means the reasoning is written down once, rather than as
//! a lint exception at each of a dozen `as` casts.

/// A byte count or timestamp, for arithmetic or display in JavaScript.
#[expect(
    clippy::cast_precision_loss,
    reason = "integers below 2^53 are exact in f64; sizes and timestamps are far below it"
)]
pub fn to_f64(value: u64) -> f64 {
    value as f64
}

/// A length or index as an `f64`.
#[expect(
    clippy::cast_precision_loss,
    reason = "integers below 2^53 are exact in f64; lengths are far below it"
)]
pub fn len_to_f64(value: usize) -> f64 {
    value as f64
}

/// An `f64` from JavaScript as a byte count.
///
/// Negative, `NaN` and infinite inputs clamp to zero rather than wrapping into
/// an enormous length.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to a finite, non-negative range first"
)]
pub fn to_u64(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        value as u64
    } else {
        0
    }
}

/// An `f64` as a record count, saturating rather than wrapping.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to a finite range within u32 first"
)]
pub fn to_u32(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        value as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_floats_clamp_instead_of_wrapping() {
        assert_eq!(to_u64(-1.0), 0);
        assert_eq!(to_u64(f64::NAN), 0);
        assert_eq!(to_u64(f64::INFINITY), 0);
        assert_eq!(to_u64(1024.9), 1024);

        assert_eq!(to_u32(-5.0), 0);
        assert_eq!(to_u32(f64::NAN), 0);
        assert_eq!(to_u32(f64::INFINITY), u32::MAX);
        assert_eq!(to_u32(1e30), u32::MAX);
        assert_eq!(to_u32(7.9), 7);
    }

    #[test]
    fn integer_conversions_round_trip_at_realistic_sizes() {
        for value in [0u64, 1, 4096, 2 * 1024 * 1024 * 1024, 1 << 52] {
            assert_eq!(to_u64(to_f64(value)), value);
        }
    }
}
