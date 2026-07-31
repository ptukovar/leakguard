//! `leakguard` -- fast, zero-dependency redaction of secrets and PII from text.
//!
//! `leakguard` finds and removes sensitive data from arbitrary strings and log
//! lines. It has **no dependencies**, is `#![no_std]`-friendly (with `alloc`),
//! and ships with a small, hand-written scanner for every detector (no regex
//! engine).
//!
//! Enable the `parallel` feature to use `Redactor::find_parallel` and
//! `Redactor::clean_parallel` for large inputs. These APIs use scoped standard
//! library threads and keep the crate dependency-free.
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
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "parallel")]
use core::sync::atomic::{AtomicUsize, Ordering};

pub mod detectors;
mod types;

pub use detectors::{Detector, FnDetector, LiteralDetector};
pub use types::{Kind, LocatedMatch, Match, RedactionStats};

#[cfg(feature = "parallel")]
const PARALLEL_INPUT_THRESHOLD: usize = 256 * 1024;

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
    /// Replace each match using a template string where `{LABEL}` or `{KIND}` is
    /// replaced with the uppercase kind label (e.g. `EMAIL`) and `{label}` or
    /// `{kind}` is replaced with the lowercase label (`email`).
    ///
    /// ```
    /// use leakguard::{Mask, Redactor};
    ///
    /// let r = Redactor::new().mask(Mask::template("<{LABEL}>"));
    /// assert_eq!(r.clean("ip 10.0.0.1"), "ip <IPV4>");
    /// ```
    Template(Cow<'static, str>),
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

    /// Build a template mask from either a string literal or an owned string.
    ///
    /// Placeholders `{LABEL}` or `{KIND}` are replaced with the uppercase kind
    /// label (e.g. `EMAIL`), while `{label}` / `{kind}` are replaced with
    /// lowercase (`email`).
    ///
    /// ```
    /// use leakguard::{Mask, Redactor};
    ///
    /// let tmpl = Redactor::new().mask(Mask::template("<{LABEL}>"));
    /// # let _ = tmpl;
    /// ```
    pub fn template<S>(s: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Template(s.into())
    }
}

/// The main entry point: configure detectors + a [`Mask`], then [`clean`](Redactor::clean).
pub struct Redactor {
    detectors: Vec<Box<dyn Detector>>,
    mask: Mask,
    ignored: Vec<String>,
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
            ignored: Vec::new(),
        }
    }

    /// Create a redactor with **no** detectors. Add your own with
    /// [`with_detector`](Redactor::with_detector).
    pub fn empty() -> Self {
        Self {
            detectors: Vec::new(),
            mask: Mask::Label,
            ignored: Vec::new(),
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
            ignored: Vec::new(),
        }
    }

    /// Set the masking strategy (builder style).
    pub fn mask(mut self, mask: Mask) -> Self {
        self.mask = mask;
        self
    }

    /// Ignore matches whose text equals the given literal value (builder style).
    ///
    /// Matches on the allowlist are skipped by all detection and redaction
    /// methods ([`find`](Self::find), [`clean`](Self::clean),
    /// [`is_dirty`](Self::is_dirty), and their parallel equivalents).
    pub fn ignore<S: AsRef<str>>(mut self, value: S) -> Self {
        self.ignored.push(String::from(value.as_ref()));
        self
    }

    /// Ignore matches whose text equals any literal value in `values` (builder style).
    pub fn ignore_list<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for val in values {
            self.ignored.push(String::from(val.as_ref()));
        }
        self
    }

    /// Return `true` if `text` is on this redactor's allowlist.
    pub fn is_ignored(&self, text: &str) -> bool {
        self.ignored.iter().any(|s| s == text)
    }

    /// Add a literal word or phrase detector (builder style).
    ///
    /// Any occurrence of `word` in the input will be detected as `kind`.
    /// Literal detectors take priority over default built-in detectors on overlaps.
    pub fn redact_literal<S: AsRef<str>>(mut self, word: S, kind: Kind) -> Self {
        self.detectors
            .insert(0, Box::new(detectors::LiteralDetector::new([word], kind)));
        self
    }

    /// Add multiple literal words or phrases to be detected as `kind` (builder style).
    ///
    /// Literal detectors take priority over default built-in detectors on overlaps.
    pub fn redact_words<I, S>(mut self, words: I, kind: Kind) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.detectors
            .insert(0, Box::new(detectors::LiteralDetector::new(words, kind)));
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
        resolve_overlaps(self.find_raw(input))
    }

    /// Find all matches in `input`, returning them with 1-indexed line and
    /// UTF-8 character column positions.
    pub fn find_located(&self, input: &str) -> Vec<LocatedMatch> {
        locate_matches(input, self.find(input))
    }

    /// Return statistics summarizing the matches found in `input`.
    pub fn stats(&self, input: &str) -> RedactionStats {
        let matches = self.find(input);
        let mut stats = RedactionStats::new();
        stats.record_all(&matches);
        stats
    }

    /// Return both the cleaned string and statistics summarizing what was redacted.
    pub fn clean_with_stats(&self, input: &str) -> (String, RedactionStats) {
        let matches = self.find(input);
        let mut stats = RedactionStats::new();
        stats.record_all(&matches);
        let cleaned = self.render_matches(input, &matches);
        (cleaned, stats)
    }

    /// Return a vector of cleaned copies along with combined statistics for an iterator of input strings.
    pub fn clean_iter_with_stats<I, S>(&self, inputs: I) -> (Vec<String>, RedactionStats)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut stats = RedactionStats::new();
        let cleaned = inputs
            .into_iter()
            .map(|s| {
                let (c, s_chunk) = self.clean_with_stats(s.as_ref());
                stats.merge(&s_chunk);
                c
            })
            .collect();
        (cleaned, stats)
    }

    /// Find all matches using detector-level parallelism for large inputs.
    ///
    /// The worker count is derived from the available CPU parallelism while
    /// leaving one CPU available for the caller's other work. Small inputs and
    /// configurations with fewer than two workers or detectors automatically
    /// use the serial path. Match ordering and overlap resolution are identical
    /// to [`find`](Self::find).
    #[cfg(feature = "parallel")]
    pub fn find_parallel(&self, input: &str) -> Vec<Match> {
        let workers = parallel_worker_count().min(self.detectors.len());
        if input.len() < PARALLEL_INPUT_THRESHOLD || workers < 2 {
            return self.find(input);
        }
        resolve_overlaps(self.find_raw_parallel(input, workers))
    }

    /// Find all matches using detector-level parallelism, returning them with
    /// 1-indexed line and UTF-8 character column positions.
    #[cfg(feature = "parallel")]
    pub fn find_located_parallel(&self, input: &str) -> Vec<LocatedMatch> {
        locate_matches(input, self.find_parallel(input))
    }

    /// Return statistics summarizing the matches found in `input` using detector-level parallelism.
    #[cfg(feature = "parallel")]
    pub fn stats_parallel(&self, input: &str) -> RedactionStats {
        let matches = self.find_parallel(input);
        let mut stats = RedactionStats::new();
        stats.record_all(&matches);
        stats
    }

    /// Return both the cleaned string and statistics using detector-level parallelism.
    #[cfg(feature = "parallel")]
    pub fn clean_with_stats_parallel(&self, input: &str) -> (String, RedactionStats) {
        let matches = self.find_parallel(input);
        let mut stats = RedactionStats::new();
        stats.record_all(&matches);
        let cleaned = self.render_matches(input, &matches);
        (cleaned, stats)
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
            if self.ignored.is_empty() {
                if !v.is_empty() {
                    return true;
                }
            } else if v
                .iter()
                .any(|matched| !self.is_ignored(matched.text(input)))
            {
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
        self.render_matches(input, &matches)
    }

    /// Return a cleaned copy using detector-level parallelism for large inputs.
    ///
    /// This uses the same masking and overlap rules as [`clean`](Self::clean)
    /// and automatically falls back to serial processing when parallelism would
    /// add more overhead than useful work.
    #[cfg(feature = "parallel")]
    pub fn clean_parallel(&self, input: &str) -> String {
        let matches = self.find_parallel(input);
        self.render_matches(input, &matches)
    }

    fn find_raw(&self, input: &str) -> Vec<(usize, Match)> {
        let mut raw = Vec::new();
        let mut buf = Vec::new();
        for (priority, detector) in self.detectors.iter().enumerate() {
            buf.clear();
            detector.detect(input, &mut buf);
            raw.extend(
                buf.drain(..)
                    .filter(|matched| !self.is_ignored(matched.text(input)))
                    .map(|matched| (priority, matched)),
            );
        }
        raw
    }

    #[cfg(feature = "parallel")]
    fn find_raw_parallel(&self, input: &str, workers: usize) -> Vec<(usize, Match)> {
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for _ in 0..workers {
                handles.push(scope.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let priority = next.fetch_add(1, Ordering::Relaxed);
                        let Some(detector) = self.detectors.get(priority) else {
                            break;
                        };
                        let mut matches = Vec::new();
                        detector.detect(input, &mut matches);
                        local.extend(
                            matches
                                .into_iter()
                                .filter(|matched| !self.is_ignored(matched.text(input)))
                                .map(|matched| (priority, matched)),
                        );
                    }
                    local
                }));
            }

            let mut raw = Vec::new();
            for handle in handles {
                match handle.join() {
                    Ok(mut local) => raw.append(&mut local),
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
            raw
        })
    }

    fn render_matches(&self, input: &str, matches: &[Match]) -> String {
        if matches.is_empty() {
            return String::from(input);
        }
        let mut out = String::with_capacity(input.len());
        let mut cursor = 0;
        for m in matches {
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
            Mask::Template(tmpl) => {
                let label_upper = m.kind.label();
                let mut out = String::with_capacity(tmpl.len() + label_upper.len());
                let mut rest = tmpl.as_ref();
                while let Some(idx) = rest.find('{') {
                    out.push_str(&rest[..idx]);
                    rest = &rest[idx..];
                    if let Some(end) = rest.find('}') {
                        let token = &rest[1..end];
                        match token {
                            "LABEL" | "KIND" => out.push_str(label_upper),
                            "label" | "kind" => {
                                for c in label_upper.chars() {
                                    out.push(c.to_ascii_lowercase());
                                }
                            }
                            _ => out.push_str(&rest[..=end]),
                        }
                        rest = &rest[end + 1..];
                    } else {
                        break;
                    }
                }
                out.push_str(rest);
                out
            }
        }
    }
}

#[cfg(feature = "parallel")]
fn parallel_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_sub(1).max(1))
        .unwrap_or(1)
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
    let mut kept = BTreeMap::new();
    for (_, m) in matches {
        // The nearest accepted matches on either side are the only possible
        // overlaps. A tree keeps both lookup and insertion O(log k), including
        // match-dense inputs where a sorted Vec would spend O(k) shifting.
        let overlaps_prev = kept
            .range(..=m.start)
            .next_back()
            .map(|(_, previous): (&usize, &Match)| previous.end > m.start)
            .unwrap_or(false);
        let overlaps_next = kept
            .range(m.start..)
            .next()
            .map(|(_, next)| m.end > next.start)
            .unwrap_or(false);
        if !overlaps_prev && !overlaps_next {
            kept.insert(m.start, m);
        }
    }
    kept.into_values().collect()
}

/// Compute 1-indexed line and UTF-8 character column numbers for sorted [`Match`]es in `input`.
fn locate_matches(input: &str, matches: Vec<Match>) -> Vec<LocatedMatch> {
    if matches.is_empty() {
        return Vec::new();
    }
    let mut located = Vec::with_capacity(matches.len());
    let mut current_line = 1usize;
    let mut line_start_byte = 0usize;
    let mut last_scanned_byte = 0usize;

    for m in matches {
        for (i, b) in input[last_scanned_byte..m.start].bytes().enumerate() {
            if b == b'\n' {
                current_line += 1;
                line_start_byte = last_scanned_byte + i + 1;
            }
        }
        last_scanned_byte = m.start;

        let col = input[line_start_byte..m.start].chars().count() + 1;
        located.push(LocatedMatch {
            matched: m,
            line: current_line,
            column: col,
        });
    }
    located
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

#[cfg(all(test, feature = "parallel"))]
mod parallel_tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    #[test]
    fn parallel_raw_matches_serial_with_multiple_workers() {
        let redactor = Redactor::new();
        let input = "alice@example.com 203.0.113.42 AKIAIOSFODNN7EXAMPLE";

        let serial = resolve_overlaps(redactor.find_raw(input));
        let parallel = resolve_overlaps(redactor.find_raw_parallel(input, 4));

        assert_eq!(parallel, serial);
    }

    #[test]
    fn parallel_detector_panic_propagates_to_the_caller() {
        let redactor = Redactor::empty()
            .with_detector(FnDetector::new(Kind::Custom("PANIC"), |_, _| {
                panic!("synthetic detector panic")
            }));

        let result = catch_unwind(AssertUnwindSafe(|| {
            redactor.find_raw_parallel("synthetic input", 2)
        }));

        assert!(result.is_err());
    }
}
