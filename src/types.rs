//! Core data types: [`Kind`] and [`Match`].

use core::fmt;

/// The category of sensitive data a detector matched.
///
/// This list is intentionally open-ended via [`Kind::Custom`] so users can plug
/// in their own detectors without forking the crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// An email address, e.g. `alice@example.com`.
    Email,
    /// A credit-card-like number that passes the Luhn checksum.
    CreditCard,
    /// An IPv4 address, e.g. `192.168.0.1`.
    IpV4,
    /// An IPv6 address, e.g. `2001:db8::1`.
    IpV6,
    /// A JSON Web Token (three base64url segments separated by `.`).
    Jwt,
    /// A US Social Security Number, e.g. `123-45-6789`.
    UsSsn,
    /// A MAC address, e.g. `00:1A:2B:3C:4D:5E`.
    MacAddress,
    /// An AWS access key id, e.g. `AKIA...`.
    AwsAccessKey,
    /// A phone number (loosely, an international/US style number).
    PhoneNumber,
    /// A URL containing inline `user:password@host` credentials.
    UrlCredentials,
    /// A GitHub personal access / OAuth / app token, e.g. `ghp_...`.
    GitHubToken,
    /// A Slack token, e.g. `xoxb-...`.
    SlackToken,
    /// A Stripe secret/publishable/restricted key, e.g. `sk_live_...`.
    StripeKey,
    /// A Google API key, e.g. `AIza...`.
    GoogleApiKey,
    /// An OpenAI-style API key, e.g. `sk-...`.
    OpenAiKey,
    /// A PEM-encoded private key block (`-----BEGIN ... PRIVATE KEY-----`).
    PrivateKey,
    /// An IBAN bank account number (passes the ISO 7064 mod-97 checksum).
    Iban,
    /// A generic high-entropy secret detected by [`crate::detectors::HighEntropy`].
    GenericSecret,
    /// A high-entropy token / generic secret detected by a custom rule.
    Custom(&'static str),
}

impl Kind {
    /// A short, stable, machine-friendly label (e.g. used in `[REDACTED:EMAIL]`).
    pub fn label(&self) -> &str {
        match self {
            Kind::Email => "EMAIL",
            Kind::CreditCard => "CREDIT_CARD",
            Kind::IpV4 => "IPV4",
            Kind::IpV6 => "IPV6",
            Kind::Jwt => "JWT",
            Kind::UsSsn => "US_SSN",
            Kind::MacAddress => "MAC",
            Kind::AwsAccessKey => "AWS_ACCESS_KEY",
            Kind::PhoneNumber => "PHONE",
            Kind::UrlCredentials => "URL_CREDENTIALS",
            Kind::GitHubToken => "GITHUB_TOKEN",
            Kind::SlackToken => "SLACK_TOKEN",
            Kind::StripeKey => "STRIPE_KEY",
            Kind::GoogleApiKey => "GOOGLE_API_KEY",
            Kind::OpenAiKey => "OPENAI_KEY",
            Kind::PrivateKey => "PRIVATE_KEY",
            Kind::Iban => "IBAN",
            Kind::GenericSecret => "GENERIC_SECRET",
            Kind::Custom(name) => name,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single detected span of sensitive data within the input text.
///
/// `start` and `end` are **byte offsets** into the original input and always lie
/// on UTF-8 character boundaries, so `&input[m.start..m.end]` is always valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// What kind of sensitive data this is.
    pub kind: Kind,
    /// Byte offset of the first byte of the match (inclusive).
    pub start: usize,
    /// Byte offset just past the last byte of the match (exclusive).
    pub end: usize,
}

impl Match {
    /// Create a new match.
    pub fn new(kind: Kind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }

    /// The length of the matched span in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the matched span is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Borrow the matched text out of the original `input`.
    ///
    /// # Panics
    /// Panics if the match does not belong to `input` (offsets out of range).
    pub fn text<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }
}
