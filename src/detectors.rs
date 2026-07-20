//! Built-in detectors.
//!
//! Each detector is a hand-written scanner over `&str` -- there is no regex
//! engine and no dependencies. Detectors implement [`Detector`] and return
//! byte-offset [`Match`]es.

use crate::types::{Kind, Match};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// A pluggable rule that finds sensitive spans in text.
///
/// Implement this trait to add your own detector and register it with
/// [`crate::Redactor::with_detector`].
pub trait Detector: Send + Sync {
    /// The kind of data this detector produces.
    fn kind(&self) -> Kind;

    /// Scan `input` and push any matches onto `out`.
    ///
    /// Implementations must only emit matches whose `start`/`end` fall on UTF-8
    /// character boundaries of `input`.
    fn detect(&self, input: &str, out: &mut Vec<Match>);
}

// Allow boxed detectors to be used transparently.
impl Detector for Box<dyn Detector> {
    fn kind(&self) -> Kind {
        (**self).kind()
    }
    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        (**self).detect(input, out)
    }
}

/// A detector defined by a user-supplied closure.
///
/// ```
/// use leakguard::{Kind, FnDetector, Match};
///
/// // Redact anything that looks like `TODO`.
/// let det = FnDetector::new(Kind::Custom("TODO"), |input, out| {
///     let mut from = 0;
///     while let Some(i) = input[from..].find("TODO") {
///         let start = from + i;
///         out.push(Match::new(Kind::Custom("TODO"), start, start + 4));
///         from = start + 4;
///     }
/// });
/// ```
pub struct FnDetector<F> {
    kind: Kind,
    f: F,
}

impl<F> FnDetector<F>
where
    F: Fn(&str, &mut Vec<Match>) + Send + Sync,
{
    /// Build a detector from a closure.
    pub fn new(kind: Kind, f: F) -> Self {
        Self { kind, f }
    }
}

impl<F> Detector for FnDetector<F>
where
    F: Fn(&str, &mut Vec<Match>) + Send + Sync,
{
    fn kind(&self) -> Kind {
        self.kind.clone()
    }
    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        (self.f)(input, out)
    }
}

// ---------------------------------------------------------------------------
// Small byte helpers (ASCII-only; non-ASCII bytes simply aren't word/token chars)
// ---------------------------------------------------------------------------

#[inline]
fn is_ascii_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[inline]
fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// True if `b` continues an "atom" of an email local/domain part.
#[inline]
fn is_email_atom(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

/// Find the run of bytes satisfying `pred` starting at `i`; returns end offset.
#[inline]
fn run<F: Fn(u8) -> bool>(bytes: &[u8], i: usize, pred: F) -> usize {
    let mut j = i;
    while j < bytes.len() && pred(bytes[j]) {
        j += 1;
    }
    j
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// Detects `local@domain.tld` style email addresses.
pub struct Email;

impl Detector for Email {
    fn kind(&self) -> Kind {
        Kind::Email
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'@' {
                i += 1;
                continue;
            }
            // Walk left over the local part.
            let mut start = i;
            while start > 0 && is_email_atom(b[start - 1]) {
                start -= 1;
            }
            // Local part must be non-empty and not start/end with a dot.
            if start == i || b[start] == b'.' || b[i - 1] == b'.' {
                i += 1;
                continue;
            }
            // Walk right over the domain.
            let domain_start = i + 1;
            let mut j = domain_start;
            let mut last_dot = None;
            while j < b.len() {
                let c = b[j];
                if c.is_ascii_alphanumeric() || c == b'-' {
                    j += 1;
                } else if c == b'.' {
                    last_dot = Some(j);
                    j += 1;
                } else {
                    break;
                }
            }
            // Need at least one dot, and a TLD of >= 2 letters after it.
            if let Some(dot) = last_dot {
                let tld = &b[dot + 1..j];
                if tld.len() >= 2
                    && tld.iter().all(|c| c.is_ascii_alphabetic())
                    && dot > domain_start
                {
                    out.push(Match::new(Kind::Email, start, j));
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Credit card (Luhn-validated)
// ---------------------------------------------------------------------------

/// Detects 13–19 digit numbers (allowing spaces/hyphens) that pass the Luhn check.
pub struct CreditCard;

fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

impl Detector for CreditCard {
    fn kind(&self) -> Kind {
        Kind::CreditCard
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            let preceded_by_digit_or_sep_digit = i > 0
                && (is_ascii_digit(b[i - 1])
                    || ((b[i - 1] == b' ' || b[i - 1] == b'-')
                        && i > 1
                        && is_ascii_digit(b[i - 2])));
            if !is_ascii_digit(b[i]) || preceded_by_digit_or_sep_digit {
                i += 1;
                continue;
            }
            let mut j = i;
            let mut digits = [0u8; 19];
            let mut total_digits = 0usize;
            let mut end = i;
            while j < b.len() {
                if is_ascii_digit(b[j]) {
                    if total_digits < digits.len() {
                        digits[total_digits] = b[j];
                    }
                    total_digits += 1;
                    j += 1;
                    end = j;
                } else if (b[j] == b' ' || b[j] == b'-')
                    && j + 1 < b.len()
                    && is_ascii_digit(b[j + 1])
                {
                    j += 1;
                } else {
                    break;
                }
            }
            let trailing_digit = end < b.len() && is_ascii_digit(b[end]);
            if (13..=19).contains(&total_digits)
                && !trailing_digit
                && luhn_ok(&digits[..total_digits])
            {
                out.push(Match::new(Kind::CreditCard, i, end));
                i = end;
            } else {
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

/// Detects dotted-quad IPv4 addresses with each octet in `0..=255`.
pub struct IpV4;

impl Detector for IpV4 {
    fn kind(&self) -> Kind {
        Kind::IpV4
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if !is_ascii_digit(b[i]) || (i > 0 && (is_ascii_digit(b[i - 1]) || b[i - 1] == b'.')) {
                i += 1;
                continue;
            }
            let mut j = i;
            let mut octets = 0;
            let mut ok = true;
            while octets < 4 {
                let oct_start = j;
                j = run(b, j, is_ascii_digit);
                let len = j - oct_start;
                if len == 0 || len > 3 {
                    ok = false;
                    break;
                }
                // Range check.
                let val: u32 = input[oct_start..j].parse().unwrap_or(999);
                if val > 255 {
                    ok = false;
                    break;
                }
                octets += 1;
                if octets < 4 {
                    if j < b.len() && b[j] == b'.' {
                        j += 1;
                    } else {
                        ok = false;
                        break;
                    }
                }
            }
            // Reject if followed by another dot+digit (would be > 4 octets) or digit.
            let trailing = j < b.len() && (is_ascii_digit(b[j]) || b[j] == b'.');
            if ok && octets == 4 && !trailing {
                out.push(Match::new(Kind::IpV4, i, j));
                i = j;
            } else {
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IPv6 (common forms incl. `::` compression)
// ---------------------------------------------------------------------------

/// Detects IPv6 addresses, including `::`-compressed forms.
pub struct IpV6;

fn looks_like_ipv6(s: &str) -> bool {
    if !s.contains(':') {
        return false;
    }
    let double = s.matches("::").count();
    if double > 1 {
        return false;
    }
    let groups: Vec<&str> = s.split(':').collect();
    if groups.len() < 3 {
        return false;
    }
    let mut hex_groups = 0;
    for g in &groups {
        if g.is_empty() {
            continue; // from `::`
        }
        if g.len() > 4 || !g.bytes().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        hex_groups += 1;
    }
    if double == 1 {
        hex_groups <= 7
    } else {
        groups.len() == 8 && hex_groups == 8
    }
}

impl Detector for IpV6 {
    fn kind(&self) -> Kind {
        Kind::IpV6
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let is_tok = |c: u8| c.is_ascii_hexdigit() || c == b':';
        let mut i = 0;
        while i < b.len() {
            if !is_tok(b[i]) || (i > 0 && is_tok(b[i - 1])) {
                i += 1;
                continue;
            }
            let j = run(b, i, is_tok);
            let candidate = &input[i..j];
            if looks_like_ipv6(candidate) {
                out.push(Match::new(Kind::IpV6, i, j));
            }
            i = j.max(i + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

/// Detects JSON Web Tokens: three base64url segments separated by dots,
/// where the header begins with the standard `eyJ` prefix.
pub struct Jwt;

impl Detector for Jwt {
    fn kind(&self) -> Kind {
        Kind::Jwt
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i + 3 <= b.len() {
            // JWT headers are base64url of `{"...` which starts with `eyJ`.
            if &b[i..i + 3] != b"eyJ" || (i > 0 && is_b64url(b[i - 1])) {
                i += 1;
                continue;
            }
            let seg1 = run(b, i, is_b64url);
            if seg1 >= b.len() || b[seg1] != b'.' {
                i += 1;
                continue;
            }
            let seg2_start = seg1 + 1;
            let seg2 = run(b, seg2_start, is_b64url);
            if seg2 == seg2_start || seg2 >= b.len() || b[seg2] != b'.' {
                i += 1;
                continue;
            }
            let seg3_start = seg2 + 1;
            let seg3 = run(b, seg3_start, is_b64url);
            if seg3 == seg3_start {
                i += 1;
                continue;
            }
            out.push(Match::new(Kind::Jwt, i, seg3));
            i = seg3;
        }
    }
}

// ---------------------------------------------------------------------------
// US SSN
// ---------------------------------------------------------------------------

/// Detects US Social Security Numbers in `AAA-GG-SSSS` form.
pub struct UsSsn;

impl Detector for UsSsn {
    fn kind(&self) -> Kind {
        Kind::UsSsn
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        let mut i = 0;
        while i + 11 <= n {
            let win = &b[i..i + 11];
            let shape = win[0..3].iter().all(|c| is_ascii_digit(*c))
                && win[3] == b'-'
                && win[4..6].iter().all(|c| is_ascii_digit(*c))
                && win[6] == b'-'
                && win[7..11].iter().all(|c| is_ascii_digit(*c));
            let bounded_left = i == 0 || !is_ascii_digit(b[i - 1]);
            let bounded_right = i + 11 == n || !is_ascii_digit(b[i + 11]);
            if shape && bounded_left && bounded_right {
                // Area number 000, 666, 900-999 are never valid. Use byte
                // slices here so scanning arbitrary UTF-8 never slices through
                // a multibyte character.
                let invalid_area = &b[i..i + 3] == b"000" || &b[i..i + 3] == b"666" || b[i] == b'9';
                let invalid_group = &b[i + 4..i + 6] == b"00";
                let invalid_serial = &b[i + 7..i + 11] == b"0000";
                if !invalid_area && !invalid_group && !invalid_serial {
                    out.push(Match::new(Kind::UsSsn, i, i + 11));
                    i += 11;
                    continue;
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

/// Detects MAC addresses like `00:1A:2B:3C:4D:5E` or `00-1a-2b-3c-4d-5e`.
pub struct MacAddress;

impl Detector for MacAddress {
    fn kind(&self) -> Kind {
        Kind::MacAddress
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        let mut i = 0;
        while i + 17 <= n {
            let sep = b[i + 2];
            if sep != b':' && sep != b'-' {
                i += 1;
                continue;
            }
            let mut ok = true;
            for k in 0..6 {
                let off = i + k * 3;
                if !(b[off].is_ascii_hexdigit() && b[off + 1].is_ascii_hexdigit()) {
                    ok = false;
                    break;
                }
                if k < 5 && b[off + 2] != sep {
                    ok = false;
                    break;
                }
            }
            let bounded_left = i == 0 || !b[i - 1].is_ascii_hexdigit();
            let bounded_right = i + 17 == n || !(b[i + 17].is_ascii_hexdigit() || b[i + 17] == sep);
            if ok && bounded_left && bounded_right {
                out.push(Match::new(Kind::MacAddress, i, i + 17));
                i += 17;
            } else {
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AWS access key id
// ---------------------------------------------------------------------------

/// Detects AWS access key ids (`AKIA`/`ASIA`/`AGPA`/... + 16 uppercase/digits).
pub struct AwsAccessKey;

const AWS_PREFIXES: [&[u8; 4]; 7] = [
    b"AKIA", b"ASIA", b"AGPA", b"AIDA", b"AROA", b"AIPA", b"ANPA",
];

impl Detector for AwsAccessKey {
    fn kind(&self) -> Kind {
        Kind::AwsAccessKey
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        let mut i = 0;
        while i + 20 <= n {
            let prefix = &b[i..i + 4];
            let is_prefix = AWS_PREFIXES.iter().any(|p| p.as_slice() == prefix);
            let bounded_left = i == 0 || !(b[i - 1].is_ascii_alphanumeric());
            if is_prefix
                && bounded_left
                && b[i + 4..i + 20]
                    .iter()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                let bounded_right = i + 20 == n || !b[i + 20].is_ascii_alphanumeric();
                if bounded_right {
                    out.push(Match::new(Kind::AwsAccessKey, i, i + 20));
                    i += 20;
                    continue;
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// URL credentials (scheme://user:pass@host)
// ---------------------------------------------------------------------------

/// Detects inline credentials in URLs, e.g. `https://user:secret@host`.
///
/// The match covers the whole `scheme://user:pass@` prefix so the password is
/// always removed.
pub struct UrlCredentials;

impl Detector for UrlCredentials {
    fn kind(&self) -> Kind {
        Kind::UrlCredentials
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let needle = "://";
        let mut from = 0;
        while let Some(rel) = input[from..].find(needle) {
            let sep = from + rel;
            // Find the start of the scheme by walking left over scheme chars.
            let b = input.as_bytes();
            let mut scheme_start = sep;
            while scheme_start > 0
                && (b[scheme_start - 1].is_ascii_alphanumeric()
                    || matches!(b[scheme_start - 1], b'+' | b'.' | b'-'))
            {
                scheme_start -= 1;
            }
            let auth_start = sep + needle.len();
            // userinfo ends at the first '@' that precedes the next '/' '?' '#'.
            let rest = &input[auth_start..];
            let at = rest.find('@');
            let path = rest.find(['/', '?', '#']);
            let has_userinfo = match (at, path) {
                (Some(a), Some(p)) => a < p,
                (Some(_), None) => true,
                _ => false,
            };
            if scheme_start < sep && has_userinfo {
                let at_abs = auth_start + at.unwrap();
                let userinfo = &input[auth_start..at_abs];
                // Only treat as credentials if there's a colon (user:pass).
                if userinfo.contains(':') {
                    out.push(Match::new(Kind::UrlCredentials, auth_start, at_abs));
                }
            }
            from = auth_start;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for token-style detectors
// ---------------------------------------------------------------------------

/// True if `b` is a typical secret/token body character (alnum, `-`, `_`).
#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Left boundary check: the byte before `i` must not be a token char.
#[inline]
fn bounded_left(b: &[u8], i: usize) -> bool {
    i == 0 || !is_token_char(b[i - 1])
}

/// Right boundary check: the byte at `end` must not be a token char.
#[inline]
fn bounded_right(b: &[u8], end: usize) -> bool {
    end >= b.len() || !is_token_char(b[end])
}

/// Generic prefix scanner: finds `prefix` (when properly bounded) followed by a
/// run of token chars, and emits a match if the body length is within
/// `min_body..=max_body`. The match span covers the prefix + body.
fn scan_prefixed(
    input: &str,
    prefix: &str,
    min_body: usize,
    max_body: usize,
    kind: Kind,
    out: &mut Vec<Match>,
) {
    let b = input.as_bytes();
    let plen = prefix.len();
    let pb = prefix.as_bytes();
    if plen == 0 || b.len() < plen {
        return;
    }
    let mut i = 0;
    while i + plen <= b.len() {
        if &b[i..i + plen] == pb && bounded_left(b, i) {
            let body_start = i + plen;
            let body_end = run(b, body_start, is_token_char);
            let body_len = body_end - body_start;
            if body_len >= min_body && body_len <= max_body {
                out.push(Match::new(kind.clone(), i, body_end));
                i = body_end;
                continue;
            }
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// GitHub tokens
// ---------------------------------------------------------------------------

/// Detects GitHub tokens: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`.
///
/// See <https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/>.
pub struct GitHubToken;

impl Detector for GitHubToken {
    fn kind(&self) -> Kind {
        Kind::GitHubToken
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        // Fine-grained PATs are longer; check them first so the longer match wins.
        scan_prefixed(input, "github_pat_", 20, 200, Kind::GitHubToken, out);
        for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            scan_prefixed(input, p, 30, 255, Kind::GitHubToken, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Slack tokens
// ---------------------------------------------------------------------------

/// Detects Slack tokens: `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxo-`.
pub struct SlackToken;

impl Detector for SlackToken {
    fn kind(&self) -> Kind {
        Kind::SlackToken
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        for p in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxo-"] {
            scan_prefixed(input, p, 10, 255, Kind::SlackToken, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Stripe keys
// ---------------------------------------------------------------------------

/// Detects Stripe API keys: `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`,
/// `pk_live_`, `pk_test_`.
pub struct StripeKey;

impl Detector for StripeKey {
    fn kind(&self) -> Kind {
        Kind::StripeKey
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        for p in [
            "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
        ] {
            scan_prefixed(input, p, 10, 255, Kind::StripeKey, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Google API keys
// ---------------------------------------------------------------------------

/// Detects Google API keys: `AIza` followed by 35 token characters (39 total).
pub struct GoogleApiKey;

impl Detector for GoogleApiKey {
    fn kind(&self) -> Kind {
        Kind::GoogleApiKey
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i + 39 <= b.len() {
            if &b[i..i + 4] == b"AIza"
                && bounded_left(b, i)
                && b[i + 4..i + 39].iter().all(|&c| is_token_char(c))
                && bounded_right(b, i + 39)
            {
                out.push(Match::new(Kind::GoogleApiKey, i, i + 39));
                i += 39;
            } else {
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OpenAI keys
// ---------------------------------------------------------------------------

/// Detects OpenAI-style API keys: `sk-` (optionally `sk-proj-`) + a long body.
///
/// To avoid clashing with Stripe `sk_...` keys (underscore) this only matches the
/// hyphenated `sk-` form used by OpenAI.
pub struct OpenAiKey;

impl Detector for OpenAiKey {
    fn kind(&self) -> Kind {
        Kind::OpenAiKey
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        // Project keys (`sk-proj-...`) first so the longer prefix wins on overlap.
        scan_prefixed(input, "sk-proj-", 20, 255, Kind::OpenAiKey, out);
        scan_prefixed(input, "sk-", 20, 255, Kind::OpenAiKey, out);
    }
}

// ---------------------------------------------------------------------------
// PEM private keys
// ---------------------------------------------------------------------------

/// Detects PEM private-key blocks, e.g. `-----BEGIN RSA PRIVATE KEY----- ... -----END ...-----`.
///
/// The whole block (including the base64 body) is matched so nothing leaks.
pub struct PrivateKey;

impl Detector for PrivateKey {
    fn kind(&self) -> Kind {
        Kind::PrivateKey
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let begin = "-----BEGIN ";
        let mut from = 0;
        while let Some(rel) = input[from..].find(begin) {
            let start = from + rel;
            let after = start + begin.len();
            // The header must mention PRIVATE KEY before the closing dashes.
            let header_end = match input[after..].find("-----") {
                Some(h) => after + h,
                None => break,
            };
            let header = &input[after..header_end];
            if !header.contains("PRIVATE KEY") {
                from = after;
                continue;
            }
            // Find the matching END line and consume through its trailing dashes.
            let end_marker = "-----END ";
            if let Some(erel) = input[header_end..].find(end_marker) {
                let end_label_start = header_end + erel + end_marker.len();
                if let Some(drel) = input[end_label_start..].find("-----") {
                    let end = end_label_start + drel + 5; // include closing dashes
                    out.push(Match::new(Kind::PrivateKey, start, end));
                    from = end;
                    continue;
                }
            }
            from = after;
        }
    }
}

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

/// Detects IBANs (International Bank Account Numbers) that pass the ISO 7064
/// mod-97 checksum. Matches the compact form (no spaces), e.g. `DE89...`.
pub struct Iban;

fn iban_mod97_ok(s: &str) -> bool {
    // Rearrange: move first 4 chars to the end, then map letters A=10..Z=35.
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut remainder: u32 = 0;
    // Process bytes[4..] then bytes[0..4].
    let order = (4..n).chain(0..4);
    for idx in order {
        let c = bytes[idx];
        if c.is_ascii_digit() {
            remainder = (remainder * 10 + (c - b'0') as u32) % 97;
        } else if c.is_ascii_uppercase() {
            let v = (c - b'A' + 10) as u32; // two digits
            remainder = (remainder * 100 + v) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

impl Detector for Iban {
    fn kind(&self) -> Kind {
        Kind::Iban
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        let mut i = 0;
        while i < n {
            // IBAN starts with two uppercase letters then two digits.
            let head_ok = i + 4 <= n
                && b[i].is_ascii_uppercase()
                && b[i + 1].is_ascii_uppercase()
                && b[i + 2].is_ascii_digit()
                && b[i + 3].is_ascii_digit()
                && bounded_left(b, i);
            if !head_ok {
                i += 1;
                continue;
            }
            // Consume the alphanumeric body (uppercase letters + digits only).
            let mut j = i;
            while j < n && (b[j].is_ascii_uppercase() || b[j].is_ascii_digit()) {
                j += 1;
            }
            let len = j - i;
            // IBANs are 15..=34 chars. Don't match if a token char follows.
            if (15..=34).contains(&len) && bounded_right(b, j) {
                let candidate = &input[i..j];
                if iban_mod97_ok(candidate) {
                    out.push(Match::new(Kind::Iban, i, j));
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

/// Detects phone numbers in common international / North-American formats, e.g.
/// `+1 (415) 555-0132`, `+44 20 7946 0958`, `415-555-0132`.
///
/// This is intentionally conservative: it requires either a leading `+` country
/// code or a grouped/separated layout, and at least 7 digits, to limit false
/// positives on plain integers.
pub struct PhoneNumber;

impl Detector for PhoneNumber {
    fn kind(&self) -> Kind {
        Kind::PhoneNumber
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        // Separators allowed *inside* a phone number (not '+', which is leading only).
        let is_sep = |c: u8| matches!(c, b'-' | b'.' | b' ' | b'(' | b')');
        let mut i = 0;
        while i < n {
            let plus = b[i] == b'+';
            let starts = (plus || b[i].is_ascii_digit() || b[i] == b'(')
                && (i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'+'));
            if !starts {
                i += 1;
                continue;
            }
            // Walk the candidate run. '+' is only valid at the very start.
            let mut j = if plus { i + 1 } else { i };
            let mut digits = 0usize;
            let mut last_digit_end = i;
            let mut internal_seps = 0usize;
            let mut seen_digit = false;
            while j < n {
                let c = b[j];
                if c.is_ascii_digit() {
                    digits += 1;
                    last_digit_end = j + 1;
                    seen_digit = true;
                    j += 1;
                } else if is_sep(c) {
                    // Only count as internal once we've seen a digit and another follows.
                    if seen_digit {
                        internal_seps += 1;
                    }
                    j += 1;
                } else {
                    break;
                }
            }
            let end = last_digit_end; // trim trailing separators
                                      // Plausible phone: 7..=15 digits, and grouping evidence (leading '+'
                                      // or at least one separator that sits between digits).
            let trailing_ok = bounded_right(b, end) && !(end < n && b[end] == b'@');
            // Ensure at least one separator is genuinely between two digits.
            let has_grouping = plus || (internal_seps >= 1 && grouped_between_digits(&b[i..end]));
            let plausible = (7..=15).contains(&digits) && has_grouping && trailing_ok;
            if plausible {
                out.push(Match::new(Kind::PhoneNumber, i, end));
                i = end.max(i + 1);
            } else {
                i = j.max(i + 1);
            }
        }
    }
}

/// True if at least one separator in `s` has a digit on both sides.
fn grouped_between_digits(s: &[u8]) -> bool {
    let is_sep = |c: u8| matches!(c, b'-' | b'.' | b' ' | b'(' | b')');
    let mut prev_digit = false;
    let mut pending_sep = false;
    for &c in s {
        if c.is_ascii_digit() {
            if pending_sep && prev_digit {
                return true;
            }
            prev_digit = true;
            pending_sep = false;
        } else if is_sep(c) {
            if prev_digit {
                pending_sep = true;
            }
        } else {
            prev_digit = false;
            pending_sep = false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Generic high-entropy secret
// ---------------------------------------------------------------------------

/// Detects generic high-entropy tokens (e.g. random API keys / hex secrets)
/// that the prefix-based detectors don't know about.
///
/// This is **opt-in** because, by nature, it is the most false-positive-prone
/// detector. It looks for long runs of token characters whose Shannon entropy
/// exceeds a configurable threshold.
///
/// ```
/// use leakguard::{Redactor, detectors::HighEntropy};
///
/// let s = Redactor::empty().with_detector(HighEntropy::default());
/// let secret = "s3Cr3tT0k3n_8f3aB91cD2eF74gH05iJ16kL27mN";
/// assert!(s.is_dirty(secret));
/// assert!(!s.is_dirty("the quick brown fox jumps"));
/// ```
pub struct HighEntropy {
    /// Minimum length of a token-character run to consider (default 20).
    pub min_len: usize,
    /// Minimum Shannon entropy in bits/char to flag (default 3.5).
    pub min_entropy: f64,
}

impl Default for HighEntropy {
    fn default() -> Self {
        Self {
            min_len: 20,
            min_entropy: 3.5,
        }
    }
}

impl HighEntropy {
    /// Build a detector with a custom minimum length and entropy threshold.
    pub fn new(min_len: usize, min_entropy: f64) -> Self {
        Self {
            min_len,
            min_entropy,
        }
    }
}

#[cfg(feature = "std")]
fn shannon_entropy(s: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &c in s {
        counts[c as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * (p.log2());
        }
    }
    entropy
}

// Without std there is no `f64::log2`; fall back to a cheap distinct-char ratio.
#[cfg(not(feature = "std"))]
fn shannon_entropy(s: &[u8]) -> f64 {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &c in s {
        if !seen[c as usize] {
            seen[c as usize] = true;
            distinct += 1;
        }
    }
    // Approximate bits/char by ceil(log2(distinct)) using an integer bit length.
    if distinct <= 1 {
        0.0
    } else {
        (usize::BITS - (distinct - 1).leading_zeros()) as f64
    }
}

impl Detector for HighEntropy {
    fn kind(&self) -> Kind {
        Kind::GenericSecret
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let n = b.len();
        let mut i = 0;
        while i < n {
            if !is_token_char(b[i]) || !bounded_left(b, i) {
                i += 1;
                continue;
            }
            let end = run(b, i, is_token_char);
            let span = &b[i..end];
            if span.len() >= self.min_len {
                // Require a mix: at least one digit and one letter, to skip words.
                let has_digit = span.iter().any(|c| c.is_ascii_digit());
                let has_alpha = span.iter().any(|c| c.is_ascii_alphabetic());
                if has_digit && has_alpha && shannon_entropy(span) >= self.min_entropy {
                    out.push(Match::new(Kind::GenericSecret, i, end));
                }
            }
            i = end.max(i + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Azure Connection String
// ---------------------------------------------------------------------------

/// Detects Azure storage connection strings (`DefaultEndpointsProtocol=...` or `AccountKey=...`).
pub struct AzureConnectionString;

impl Detector for AzureConnectionString {
    fn kind(&self) -> Kind {
        Kind::AzureConnectionString
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        for prefix in [&b"DefaultEndpointsProtocol="[..], &b"AccountKey="[..]] {
            let plen = prefix.len();
            let mut i = 0;
            while i + plen <= b.len() {
                if &b[i..i + plen] == prefix && bounded_left(b, i) {
                    let mut start = i;
                    while start > 0
                        && b[start - 1] != b';'
                        && b[start - 1] != b'"'
                        && b[start - 1] != b'\''
                        && b[start - 1] != b'\n'
                        && b[start - 1] != b' '
                    {
                        start -= 1;
                    }
                    let mut end = i + plen;
                    while end < b.len() && b[end] != b'\n' && b[end] != b'"' && b[end] != b'\'' {
                        end += 1;
                    }
                    if end > start + 20 {
                        out.push(Match::new(Kind::AzureConnectionString, start, end));
                        i = end;
                        continue;
                    }
                }
                i += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram Bot Token
// ---------------------------------------------------------------------------

/// Detects Telegram bot API tokens (`<bot_id>:<token>`).
pub struct TelegramToken;

impl Detector for TelegramToken {
    fn kind(&self) -> Kind {
        Kind::TelegramToken
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        let b = input.as_bytes();
        let mut i = 0;
        while i + 40 <= b.len() {
            if b[i].is_ascii_digit() && bounded_left(b, i) {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                let digits_len = j - i;
                if (8..=11).contains(&digits_len) && j < b.len() && b[j] == b':' {
                    let token_start = j + 1;
                    let token_end = run(b, token_start, is_token_char);
                    let token_len = token_end - token_start;
                    if (30..=50).contains(&token_len) && bounded_right(b, token_end) {
                        out.push(Match::new(Kind::TelegramToken, i, token_end));
                        i = token_end;
                        continue;
                    }
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Discord Token
// ---------------------------------------------------------------------------

/// Detects Discord bot or user tokens.
pub struct DiscordToken;

impl Detector for DiscordToken {
    fn kind(&self) -> Kind {
        Kind::DiscordToken
    }

    fn detect(&self, input: &str, out: &mut Vec<Match>) {
        scan_prefixed(input, "mfa.", 84, 84, Kind::DiscordToken, out);

        let b = input.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if (b[i] == b'M' || b[i] == b'N' || b[i] == b'O') && bounded_left(b, i) {
                let seg1 = run(b, i, is_token_char);
                let seg1_len = seg1 - i;
                if (23..=28).contains(&seg1_len) && seg1 < b.len() && b[seg1] == b'.' {
                    let seg2_start = seg1 + 1;
                    let seg2 = run(b, seg2_start, is_token_char);
                    let seg2_len = seg2 - seg2_start;
                    if seg2_len == 6 && seg2 < b.len() && b[seg2] == b'.' {
                        let seg3_start = seg2 + 1;
                        let seg3 = run(b, seg3_start, is_token_char);
                        let seg3_len = seg3 - seg3_start;
                        if (27..=45).contains(&seg3_len) && bounded_right(b, seg3) {
                            out.push(Match::new(Kind::DiscordToken, i, seg3));
                            i = seg3;
                            continue;
                        }
                    }
                }
            }
            i += 1;
        }
    }
}
