//! Redaction-bypass regression matrix.
//!
//! Organizing principle: **a secret must never survive `clean()`**. Each
//! canonical (synthetic) secret is embedded in a range of surrounding contexts
//! that have historically defeated boundary checks -- digit prefixes, quoting,
//! JSON embedding, adjacency to other matches -- and the cleaned output must
//! not contain the secret substring.
//!
//! All values here are **synthetic**. Never add a real credential.

use leakguard::{detectors::PhoneNumber, Redactor};

/// One canonical synthetic secret per built-in detector kind.
const SECRETS: &[(&str, &str)] = &[
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("github_token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
    (
        "github_pat",
        "github_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ1234567890abcdef",
    ),
    (
        "slack_token",
        "xoxb-123456789012-1234567890123-abcdefABCDEF1234567890ab",
    ),
    ("stripe_secret", "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH"),
    ("stripe_publishable", "pk_test_TYooMQauvdEDq54NiTphI7jx"),
    ("google_api_key", "AIzaSyD1234567890abcdefghijklmnopqrstuv"),
    ("openai_key", "sk-abcdEFGH1234567890ijklMNOPqrst1234"),
    ("openai_proj_key", "sk-proj-abcdEFGH1234567890ijklMNOP1234"),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dQw4w9WgXcQ",
    ),
    (
        "telegram_token",
        "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567890",
    ),
    ("telegram_min", "12345678:abcdefghijklmnopqrstuvwxyz0123"),
    ("iban", "DE89370400440532013000"),
    ("credit_card", "4111111111111111"),
    ("credit_card_spaced", "4111 1111 1111 1111"),
    ("us_ssn", "123-45-6789"),
    ("email", "alice@example.com"),
    ("email_unicode", "p\u{ed}smena@example.com"),
    ("ipv4", "203.0.113.42"),
    ("ipv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    ("mac", "00:1A:2B:3C:4D:5E"),
];

/// Secrets whose value is *changed* by gluing a digit directly onto the front.
///
/// `1` + `203.0.113.42` is the string `1203.0.113.42`, which is not a valid
/// IPv4 address; `1` + a 16-digit PAN is a 17-digit number that fails Luhn.
/// Refusing to match these is correct behaviour, not a bypass, so the
/// digit-adjacency contexts are skipped for them. Prefix-based secrets
/// (`AKIA...`, `ghp_...`) keep their identity under a digit prefix and are
/// therefore still required to match.
const DIGIT_ADJACENCY_CHANGES_VALUE: &[&str] = &[
    "iban",
    "credit_card",
    "credit_card_spaced",
    "us_ssn",
    "ipv4",
    "ipv6",
    "mac",
];

/// Contexts that place a digit immediately before the secret with no delimiter.
const DIGIT_ADJACENT_CONTEXTS: &[&str] = &["digit_prefixed", "token_digit_prefixed"];

/// Surrounding contexts. `{}` is replaced by the secret.
const CONTEXTS: &[(&str, &str)] = &[
    ("bare", "{}"),
    ("start_of_input", "{} trailing text"),
    ("end_of_input", "leading text {}"),
    ("quoted", "\"{}\""),
    ("single_quoted", "'{}'"),
    ("json_embedded", "{\"key\":\"{}\",\"n\":1}"),
    ("comma_delimited", "a,{},b"),
    ("digit_prefixed", "1{}"),
    ("token_digit_prefixed", "v2{}"),
    ("number_then_space", "qty 7 {}"),
    ("number_then_hyphen", "id 9-{}"),
    ("after_email", "alice@example.com {}"),
    ("after_ipv4", "10.0.0.1 {}"),
    ("in_url_query", "https://api.example.com/v1?key={}"),
    ("env_assignment", "SECRET={}"),
    ("log_prefixed", "2026-06-06 12:00:00 INFO token={}"),
    ("parenthesised", "({})"),
    ("bracketed", "[{}]"),
    ("tab_separated", "field\t{}\tnext"),
];

fn contexts_for<'a>(
    kind: &'a str,
    secret: &'a str,
) -> impl Iterator<Item = (&'static str, String)> + 'a {
    let skip_digit_adjacent = DIGIT_ADJACENCY_CHANGES_VALUE.contains(&kind);
    CONTEXTS
        .iter()
        .filter(move |(name, _)| !(skip_digit_adjacent && DIGIT_ADJACENT_CONTEXTS.contains(name)))
        .map(move |(name, tmpl)| (*name, tmpl.replace("{}", secret)))
}

#[test]
fn no_secret_survives_clean_under_default_detectors() {
    let redactor = Redactor::new();
    let mut leaks = Vec::new();

    for (kind, secret) in SECRETS {
        for (ctx_name, input) in contexts_for(kind, secret) {
            let cleaned = redactor.clean(&input);
            if cleaned.contains(secret) {
                leaks.push(format!("  [{kind} / {ctx_name}] {input:?} -> {cleaned:?}"));
            }
        }
    }

    assert!(
        leaks.is_empty(),
        "{} secret(s) survived redaction:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn no_secret_survives_clean_with_phone_detector_enabled() {
    // The opt-in phone detector must not shadow higher-specificity secrets.
    let redactor = Redactor::new().with_detector(PhoneNumber);
    let mut leaks = Vec::new();

    for (kind, secret) in SECRETS {
        for (ctx_name, input) in contexts_for(kind, secret) {
            let cleaned = redactor.clean(&input);
            if cleaned.contains(secret) {
                leaks.push(format!("  [{kind} / {ctx_name}] {input:?} -> {cleaned:?}"));
            }
        }
    }

    assert!(
        leaks.is_empty(),
        "{} secret(s) survived redaction with phone enabled:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}

#[test]
fn phone_adjacent_secret_is_not_shadowed() {
    // Regression: a phone match starting earlier used to swallow the JWT.
    let redactor = Redactor::new().with_detector(PhoneNumber);
    let input = "415-555-0132eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dQw4w9WgXcQ";
    let cleaned = redactor.clean(input);
    assert!(
        cleaned.contains("[REDACTED:JWT]"),
        "JWT was shadowed: {cleaned}"
    );
}

#[test]
fn credit_card_after_unrelated_number_is_redacted() {
    // Regression for the `digit + separator` guard that vetoed real cards.
    let redactor = Redactor::new();
    for input in [
        "qty 7 4111 1111 1111 1111",
        "1 4111111111111111",
        "v2 4111111111111111",
        "id 9-4111111111111111",
        "amount 42 4111111111111111",
    ] {
        let cleaned = redactor.clean(input);
        assert!(
            cleaned.contains("[REDACTED:CREDIT_CARD]"),
            "card not redacted in {input:?} -> {cleaned:?}"
        );
    }
}

#[test]
fn overlong_digit_runs_are_still_rejected() {
    // The W1 fix must not start matching 20-digit runs.
    let redactor = Redactor::new();
    for input in [
        "41111111111111000060",
        "4111 1111 1111 1100 0060",
        "1234567890123456789012345",
    ] {
        assert_eq!(
            redactor.clean(input),
            input,
            "unexpected match in {input:?}"
        );
    }
}

#[test]
fn telegram_minimum_length_token_at_end_of_input() {
    // Regression: the loop bound skipped the shortest (39-byte) valid token.
    let redactor = Redactor::new();
    for digits in 8..=11usize {
        let token = format!("{}:{}", "1".repeat(digits), "a".repeat(30));
        for input in [token.clone(), format!("bot {token}"), format!("{token} ")] {
            let cleaned = redactor.clean(&input);
            assert!(
                cleaned.contains("[REDACTED:TELEGRAM_TOKEN]"),
                "telegram token missed in {input:?} -> {cleaned:?}"
            );
        }
    }
}

#[test]
fn letter_prefixed_tokens_are_not_over_matched() {
    // The relaxed left boundary permits a preceding *digit* only; a preceding
    // letter still means the prefix is an interior substring.
    let redactor = Redactor::new();
    for input in [
        "xAKIAIOSFODNN7EXAMPLE",
        "fooghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "notAIzaSyD1234567890abcdefghijklmnopqrstuv",
    ] {
        assert_eq!(
            redactor.clean(input),
            input,
            "unexpected match in {input:?}"
        );
    }
}
