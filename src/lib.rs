//! `leakguard` -- fast, zero-dependency redaction of secrets and PII from text.
//!
//! `leakguard` finds and removes sensitive data from arbitrary strings and log
//! lines. It has **no dependencies**, is `#![no_std]`-friendly (with `alloc`),
//! and ships with a small, hand-written scanner for every detector (no regex
//! engine).
//!
//! # Built-in detectors
//!
//! Enabled by [`Redactor::new`]:
//!
//! - **Cloud & platform keys**: AWS access keys, Google API keys, Azure storage
//!   connection strings.
//! - **Service tokens**: GitHub (`ghp_`, `github_pat_`), Slack (`xoxb-`),
//!   Stripe (`sk_live_`), OpenAI (`sk-`, `sk-proj-`), Telegram, Discord, JWTs.
//! - **Credentials**: PEM private-key blocks, `user:pass@host` URL credentials.
//! - **PII & financial**: emails, credit-card numbers (Luhn-validated), IBANs
//!   (mod-97-validated), US SSNs, IPv4/IPv6 addresses, MAC addresses.
//!
//! Opt-in (the most false-positive-prone; add with
//! [`Redactor::with_detector`]): [`detectors::PhoneNumber`] and
//! [`detectors::HighEntropy`].
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
//! let s = Redactor::new().mask(Mask::fixed("***"));
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

use alloc::borrow::Cow;
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
    ///
    /// Use `Mask::fixed("...")` for a concise constructor that accepts both
    /// string literals and owned [`String`] values.
    Fixed(Cow<'static, str>),
    /// Replace each *character* of the match with `ch`.
    Char(char),
    /// Keep the last `keep_last` characters; replace the rest with `ch`.
    ///
    /// `keep_last` is clamped so that **at least half** of the match (rounded
    /// up) is always masked. A mask can therefore never return the matched
    /// text unchanged, no matter how large `keep_last` is: asking to keep 99
    /// characters of a 16-character card still masks the leading 8.
    Partial {
        /// Number of trailing characters to preserve. Clamped to at most half
        /// the match length, so some of the value is always hidden.
        keep_last: usize,
        /// Fill character for the masked portion.
        ch: char,
    },
    /// Replace with a short, stable, non-cryptographic fingerprint so equal
    /// values stay equal. This is intended for correlation, **not** for
    /// anonymization or security against guessing/dictionary attacks.
    Hash,
}

impl Mask {
    /// Build a fixed-string mask from either a string literal or an owned string.
    ///
    /// ```
    /// use leakguard::{Mask, Redactor};
    ///
    /// let literal = Redactor::new().mask(Mask::fixed("***"));
    /// let runtime = Redactor::new().mask(Mask::fixed(String::from("<hidden>")));
    /// # let _ = (literal, runtime);
    /// ```
    pub fn fixed<S>(s: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Fixed(s.into())
    }
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
    /// This can select **any** built-in detector, including the opt-in
    /// [`Kind::PhoneNumber`] that [`Redactor::new`] leaves disabled.
    ///
    /// Unknown / [`Kind::Custom`] kinds are ignored (add those via
    /// [`with_detector`](Redactor::with_detector)).
    pub fn only(kinds: &[Kind]) -> Self {
        let detectors = all_detectors()
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
        let mut raw: Vec<(usize, Match)> = Vec::new();
        let mut buf = Vec::new();
        for (priority, d) in self.detectors.iter().enumerate() {
            buf.clear();
            d.detect(input, &mut buf);
            raw.extend(buf.drain(..).map(|m| (priority, m)));
        }
        resolve_overlaps(raw)
    }

    /// Return `true` if `input` contains any sensitive data.
    ///
    /// Short-circuits on the first detector that reports a match and reuses a
    /// single scratch buffer, so it never allocates once per detector.
    pub fn is_dirty(&self, input: &str) -> bool {
        let mut v = Vec::new();
        for d in &self.detectors {
            v.clear();
            d.detect(input, &mut v);
            if !v.is_empty() {
                return true;
            }
        }
        false
    }

    /// Return a vector of cleaned copies for an iterator of input strings.
    pub fn clean_iter<'a, I>(&self, inputs: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        inputs.into_iter().map(|s| self.clean(s)).collect()
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
            Mask::Fixed(s) => String::from(s.as_ref()),
            Mask::Char(c) => core::iter::repeat(*c)
                .take(original.chars().count())
                .collect(),
            Mask::Partial { keep_last, ch } => {
                let total = original.chars().count();
                // Never reveal more than half of a match: a masking strategy
                // must not be able to return its input verbatim.
                let keep = (*keep_last).min(total / 2);
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

/// All built-in **default** detectors, in priority order (earlier = higher
/// specificity, and wins when two matches overlap).
///
/// [`detectors::PhoneNumber`] and [`detectors::HighEntropy`] are deliberately
/// **not** included: both are the most false-positive-prone detectors, so they
/// are opt-in via [`Redactor::with_detector`].
fn default_detectors() -> Vec<Box<dyn Detector>> {
    use detectors::*;
    alloc::vec![
        // High-specificity secrets first so they win on any overlap.
        Box::new(PrivateKey) as Box<dyn Detector>,
        Box::new(AzureConnectionString),
        Box::new(TelegramToken),
        Box::new(DiscordToken),
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
    ]
}

/// Every built-in [`Kind`] that [`Redactor::only`] can construct, in the same
/// priority order as [`default_detectors`]. Includes the opt-in detectors.
fn all_detectors() -> Vec<Box<dyn Detector>> {
    let mut v = default_detectors();
    v.push(Box::new(detectors::PhoneNumber));
    v
}

/// Sort matches and drop ones overlapping a previously kept match.
///
/// Resolution order:
/// 1. **Detector priority** -- a higher-specificity detector (earlier in
///    [`default_detectors`]) wins an overlap outright, even if it starts later.
///    This stops a broad match such as a phone number from swallowing a JWT.
/// 2. Earlier start.
/// 3. Longer span.
fn resolve_overlaps(mut matches: Vec<(usize, Match)>) -> Vec<Match> {
    // Highest priority (lowest index) first; then earliest; then longest.
    matches.sort_by(|(pa, a), (pb, b)| {
        pa.cmp(pb)
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| b.len().cmp(&a.len()))
    });
    let mut kept: Vec<Match> = Vec::with_capacity(matches.len());
    for (_, m) in matches {
        // Keep only matches that don't overlap anything already accepted.
        // `kept` is maintained in start order, so a binary search locates the
        // only two candidates that can overlap `m` -- this keeps resolution
        // O(k log k) rather than O(k^2) on match-dense input.
        let idx = kept.partition_point(|k| k.start <= m.start);
        let overlaps_prev = idx > 0 && kept[idx - 1].end > m.start;
        let overlaps_next = idx < kept.len() && m.end > kept[idx].start;
        if !overlaps_prev && !overlaps_next {
            kept.insert(idx, m);
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
