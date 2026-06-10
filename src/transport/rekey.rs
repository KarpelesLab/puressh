//! Re-key scheduler — RFC 4253 §9.
//!
//! The standard requires a fresh exchange after roughly **1 GB** of data or
//! **1 hour** of wall-clock time, whichever comes first. A separate, harder
//! limit is needed to keep the packet sequence number from wrapping past
//! `u32::MAX`: a re-key is forced well before that point.
//!
//! The runtime makes the call by combining a [`RekeyPolicy`] with the
//! [`PacketCodec`]'s live counters and an `Instant` recording when the last
//! KEX finished. The policy itself is `Send + Sync`, so callers can share
//! one across connections.

#[cfg(feature = "std")]
use std::time::{Duration, Instant};

use crate::transport::packet::PacketCodec;

/// Re-key trigger thresholds. All three are evaluated and any one tripping
/// is enough to start a new KEX.
#[derive(Debug, Clone, Copy)]
pub struct RekeyPolicy {
    /// Per-direction byte cap on the on-wire stream — start a new KEX once
    /// either inbound or outbound has flowed more than this many bytes
    /// since the last completed exchange. Default `1 << 30` (1 GiB).
    pub max_bytes: u64,
    /// Wall-clock cap on how long to keep the same keys. Default 1 hour.
    /// Only honoured when the `std` feature is enabled.
    #[cfg(feature = "std")]
    pub max_duration: Duration,
    /// Sequence-counter cap. Wrapping back through zero on a 32-bit counter
    /// would reuse nonces with AEAD ciphers, so we re-key long before then.
    /// Default `1 << 31` — half the counter's range.
    pub max_seq: u32,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 1u64 << 30,
            #[cfg(feature = "std")]
            max_duration: Duration::from_secs(60 * 60),
            max_seq: 1u32 << 31,
        }
    }
}

impl RekeyPolicy {
    /// `true` if **any** threshold has been crossed. `last_kex` is the
    /// `Instant` the previous KEX completed; pass the same value across
    /// calls in the same KEX epoch.
    #[cfg(feature = "std")]
    pub fn should_rekey(&self, codec: &PacketCodec, last_kex: Instant, now: Instant) -> bool {
        if self.bytes_exceeded(codec) {
            return true;
        }
        if self.seq_exceeded(codec) {
            return true;
        }
        now.saturating_duration_since(last_kex) >= self.max_duration
    }

    /// `no_std`-friendly subset: byte and sequence checks only.
    #[cfg(not(feature = "std"))]
    pub fn should_rekey(&self, codec: &PacketCodec) -> bool {
        self.bytes_exceeded(codec) || self.seq_exceeded(codec)
    }

    fn bytes_exceeded(&self, codec: &PacketCodec) -> bool {
        codec.bytes_in >= self.max_bytes || codec.bytes_out >= self.max_bytes
    }

    fn seq_exceeded(&self, codec: &PacketCodec) -> bool {
        // Measure packets since the current KEX epoch's baseline rather than
        // the absolute counter. When strict-kex is off the sequence numbers
        // run continuously across re-KEXes (RFC 4253 §6.4); using the absolute
        // value would leave `seq >= max_seq` true forever after the first
        // crossing and re-trigger a KEX on every packet (storm).
        let in_epoch = codec.seq_in.wrapping_sub(codec.seq_in_base);
        let out_epoch = codec.seq_out.wrapping_sub(codec.seq_out_base);
        in_epoch >= self.max_seq || out_epoch >= self.max_seq
    }
}

/// Quick check for KEX message bytes — anything in `[20, 49]` is either a
/// transport-level service message (NEWKEYS=21, KEXINIT=20) or a KEX
/// algorithm-specific byte (30–34, plus reserved space for future
/// algorithms). RFC 4253 §6.5 says only these may flow while a KEX is in
/// flight, so the high-level connection loops use it to decide whether to
/// route an inbound packet through the KEX runner or the application.
pub fn is_kex_msg(b: u8) -> bool {
    matches!(b, 20 | 21 | 30..=49)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn defaults_are_one_gib_and_one_hour() {
        let p = RekeyPolicy::default();
        assert_eq!(p.max_bytes, 1u64 << 30);
        assert_eq!(p.max_duration, Duration::from_secs(3600));
        assert_eq!(p.max_seq, 1u32 << 31);
    }

    #[cfg(feature = "std")]
    #[test]
    fn fresh_codec_is_not_due_for_rekey() {
        let codec = PacketCodec::new();
        let p = RekeyPolicy::default();
        let now = Instant::now();
        assert!(!p.should_rekey(&codec, now, now));
    }

    #[cfg(feature = "std")]
    #[test]
    fn byte_threshold_triggers() {
        let mut codec = PacketCodec::new();
        let p = RekeyPolicy {
            max_bytes: 1024,
            max_duration: Duration::from_secs(60 * 60),
            max_seq: 1u32 << 31,
        };
        let now = Instant::now();
        codec.bytes_out = 1023;
        assert!(!p.should_rekey(&codec, now, now));
        codec.bytes_out = 1024;
        assert!(p.should_rekey(&codec, now, now));
    }

    #[cfg(feature = "std")]
    #[test]
    fn duration_threshold_triggers() {
        let codec = PacketCodec::new();
        let p = RekeyPolicy {
            max_bytes: 1u64 << 30,
            max_duration: Duration::from_secs(1),
            max_seq: 1u32 << 31,
        };
        let now = Instant::now();
        let then = now - Duration::from_secs(2);
        assert!(p.should_rekey(&codec, then, now));
        assert!(!p.should_rekey(&codec, now, now));
    }

    #[cfg(feature = "std")]
    #[test]
    fn seq_threshold_triggers() {
        let mut codec = PacketCodec::new();
        let p = RekeyPolicy {
            max_bytes: 1u64 << 30,
            max_duration: Duration::from_secs(60 * 60),
            max_seq: 16,
        };
        let now = Instant::now();
        codec.seq_in = 16;
        assert!(p.should_rekey(&codec, now, now));
    }

    #[test]
    fn is_kex_msg_basic() {
        assert!(is_kex_msg(20));
        assert!(is_kex_msg(21));
        assert!(is_kex_msg(30));
        assert!(is_kex_msg(49));
        assert!(!is_kex_msg(50));
        assert!(!is_kex_msg(0));
        assert!(!is_kex_msg(19));
    }
}
