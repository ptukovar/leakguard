//! `leakguard` -- fast, zero-dependency redaction of secrets and PII from text.
//!
//! `leakguard` finds and removes sensitive data -- emails, credit-card numbers,
//! IP addresses, JWTs, US SSNs, MAC addresses, AWS keys, URLs with embedded
//! credentials -- from arbitrary strings and log lines. It has **no
//! dependencies**, is `#![no_std]`-friendly (with `alloc`), and ships with a
//! small, hand-written scanner for every detector (no regex engine).
//!
//! # Quick start
//!
//! ```
//! use leakguard::Redactor;
//!
//! let s = Redactor::new(); // all default detectors enabled
//! let dirty = "Contact alice@example.com from 10.0.0.1";
//! let clean = s.clean(dirty);
//! assert_eq!(clean, "Contact [REDACTED:EMAIL] from [REDACTED:IPV4]");
//! ```
//!
//! # Choosing how things are masked
//!
//! ```
//! use leakguard::{Redactor, Mask};
//!
//! // Replace every match with a fixed string.
//! let s = Redactor::new().mask(Mask::Fixed("***"));
//! assert_eq!(s.clean("ip 10.0.0.1"), "ip ***");
//!
//! // Keep the last 4 characters of each match.
//! let s = Redactor::new().mask(Mask::Partial { keep_last: 4, ch: '*' });
//! assert_eq!(s.clean("card 4111 1111 1111 1111"), "card ***************1111");
//! ```
//!
//! # Choosing what to look for
//!
//! ```
//! use leakguard::{Redactor, Kind};
//!
//! // Only redact emails and credit cards.
//! let s = Redactor::only(&[Kind::Email, Kind::CreditCard]);
//! assert_eq!(s.clean("a@b.com 10.0.0.1"), "[REDACTED:EMAIL] 10.0.0.1");
//! ```
//!
//! # Inspecting matches without mutating
//!
//! ```
//! use leakguard::{Redactor, Kind};
//!
//! let s = Redactor::new();
//! let matches = s.find("email a@b.com");
//! assert_eq!(matches.len(), 1);
//! assert_eq!(matches[0].kind, Kind::Email);
//! assert_eq!(matches[0].text("email a@b.com"), "a@b.com");
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub mod detectors;
mod types;

pub use detectors::{Detector, FnDetector};
pub use types::{Kind, Match};

/// How a matched span is rewritten in the cleaned output.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum Mask {
    /// Replace with `[REDACTED:<LABEL>]`, e.g. `[REDACTED:EMAIL]`. The default.
    #[default]
    Label,
    /// Replace with a fixed string for every match.
    Fixed(&'static str),
    /// Replace each *character* of the match with `ch`.
    Char(char),
    /// Keep the last `keep_last` characters; replace the rest with `ch`.
    Partial {
        /// Number of trailing characters to preserve.
        keep_last: usize,
        /// Fill character for the masked portion.
        ch: char,
    },
    /// Replace with a SHA-like short fingerprint so equal values stay equal but
    /// the original is not recoverable. (Uses a fast non-cryptographic hash,
    /// suitable for correlation, **not** for security.)
    Hash,
}

/// The main entry point: configure detectors + a [`Mask`], then [`clean`](Redactor::clean).
pub struct Redactor {
    detectors: Vec<Box<dyn Detector>>,
    mask: Mask,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// Create a redactor with **all** built-in detectors and the default
    /// [`Mask::Label`] masking.
    pub fn new() -> Self {
        Self {
            detectors: default_detectors(),
            mask: Mask::Label,
        }
    }

    /// Create a redactor with **no** detectors. Add your own with
    /// [`with_detector`](Redactor::with_detector).
    pub fn empty() -> Self {
        Self {
            detectors: Vec::new(),
            mask: Mask::Label,
        }
    }

    /// Create a redactor that only enables the given built-in [`Kind`]s.
    ///
    /// Unknown / [`Kind::Custom`] kinds are ignored (add those via
    /// [`with_detector`](Redactor::with_detector)).
    pub fn only(kinds: &[Kind]) -> Self {
        let detectors = default_detectors()
            .into_iter()
            .filter(|d| kinds.contains(&d.kind()))
            .collect();
        Self {
            detectors,
            mask: Mask::Label,
        }
    }

    /// Set the masking strategy (builder style).
    pub fn mask(mut self, mask: Mask) -> Self {
        self.mask = mask;
        self
    }

    /// Add a custom detector (builder style).
    pub fn with_detector<D: Detector + 'static>(mut self, detector: D) -> Self {
        self.detectors.push(Box::new(detector));
        self
    }

    /// Remove all detectors of a given kind (builder style).
    pub fn without(mut self, kind: &Kind) -> Self {
        self.detectors.retain(|d| &d.kind() != kind);
        self
    }

    /// Find all matches in `input`, sorted by position with overlaps resolved
    /// (longer / earlier matches win). Does not modify the input.
    pub fn find(&self, input: &str) -> Vec<Match> {
        let mut raw = Vec::new();
        for d in &self.detectors {
            d.detect(input, &mut raw);
        }
        resolve_overlaps(raw)
    }

    /// Return `true` if `input` contains any sensitive data.
    pub fn is_dirty(&self, input: &str) -> bool {
        self.detectors.iter().any(|d| {
            let mut v = Vec::new();
            d.detect(input, &mut v);
            !v.is_empty()
        })
    }

    /// Return a cleaned copy of `input` with every match rewritten per the
    /// configured [`Mask`].
    pub fn clean(&self, input: &str) -> String {
        let matches = self.find(input);
        if matches.is_empty() {
            return String::from(input);
        }
        let mut out = String::with_capacity(input.len());
        let mut cursor = 0;
        for m in &matches {
            if m.start > cursor {
                out.push_str(&input[cursor..m.start]);
            }
            out.push_str(&self.render(m, &input[m.start..m.end]));
            cursor = m.end;
        }
        if cursor < input.len() {
            out.push_str(&input[cursor..]);
        }
        out
    }

    fn render(&self, m: &Match, original: &str) -> String {
        match &self.mask {
            Mask::Label => format!("[REDACTED:{}]", m.kind.label()),
            Mask::Fixed(s) => String::from(*s),
            Mask::Char(c) => core::iter::repeat(*c)
                .take(original.chars().count())
                .collect(),
            Mask::Partial { keep_last, ch } => {
                let total = original.chars().count();
                let keep = (*keep_last).min(total);
                let masked = total - keep;
                let mut s = String::with_capacity(total);
                for _ in 0..masked {
                    s.push(*ch);
                }
                s.extend(original.chars().skip(masked));
                s
            }
            Mask::Hash => format!("[{}:{:08x}]", m.kind.label(), fnv1a(original.as_bytes())),
        }
    }
}

/// All built-in detectors, in priority order (earlier = preferred on overlap ties).
fn default_detectors() -> Vec<Box<dyn Detector>> {
    use detectors::*;
    alloc::vec![
        // High-specificity secrets first so they win on any overlap.
        Box::new(PrivateKey) as Box<dyn Detector>,
        Box::new(Jwt),
        Box::new(GitHubToken),
        Box::new(SlackToken),
        Box::new(StripeKey),
        Box::new(OpenAiKey),
        Box::new(GoogleApiKey),
        Box::new(AwsAccessKey),
        Box::new(UrlCredentials),
        Box::new(Email),
        Box::new(Iban),
        Box::new(CreditCard),
        Box::new(IpV6),
        Box::new(IpV4),
        Box::new(MacAddress),
        Box::new(UsSsn),
        Box::new(PhoneNumber),
    ]
}

/// Sort matches and drop ones overlapping a previously kept match.
/// Preference: earlier start; on tie, longer span; on tie, insertion order.
fn resolve_overlaps(mut matches: Vec<Match>) -> Vec<Match> {
    matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.len().cmp(&a.len())));
    let mut kept: Vec<Match> = Vec::with_capacity(matches.len());
    let mut last_end = 0usize;
    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            kept.push(m);
        }
    }
    kept
}

/// 32-bit FNV-1a -- fast, non-cryptographic, used only for [`Mask::Hash`].
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
