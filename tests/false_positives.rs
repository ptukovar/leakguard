//! False-positive regression fixture.
//!
//! Ordinary, secret-free log output must pass through `clean()` **byte for
//! byte**. Redaction that mangles timestamps or counters breaks every
//! downstream log parser, which in practice makes the tool unusable.

use leakguard::{detectors::PhoneNumber, Redactor};

/// Realistic log lines containing no secrets and no PII.
const CLEAN_LOG: &[&str] = &[
    // Timestamps: ISO with space, ISO with `T`, bracketed, syslog-ish.
    "2026-06-06 12:00:00 INFO  boot complete in 1234 ms",
    "2026-06-06T12:00:00Z INFO  service started",
    "[2026-06-06 12:00:00] GET /health 200 15ms",
    "2026-06-07 09:15:42 WARN  retry 3 of 5 after 2000 ms",
    "2026-06-07 09:15:43 ERROR job 2024-000123 failed",
    "2026-01-15 00:00:00 INFO  rotated 1 048 576 bytes",
    "2026/06/06 12:00:00 WARN  retry scheduled",
    "Jun  6 12:00:00 host app[1234]: started",
    // Durations, counters, sizes.
    "elapsed 1 234 567 ns",
    "latency p50=12 p95=340 p99=1200",
    "cpu 12.5 mem 2048 disk 512000",
    "processed 1000000 records in 42 s",
    "range 1000000-2000000 scanned",
    "uptime 99.995 percent",
    // Versions and build metadata.
    "build 2026.06.06 commit abcdef1",
    "ver 10.4.3 build 22000",
    "upgraded from 1.2.3 to 1.2.4",
    "schema version 20260607093000 applied",
    // Identifiers that are not phone numbers.
    "id 12345",
    "plain 1234567 here",
    "year 2024 and 2025",
    "seq 1 2 3 4 5 6 7 8",
    "invoice 2024/000123 paid",
    "port 8080 bound",
    // Ordinary prose and paths.
    "the quick brown fox jumps over the lazy dog",
    "reading /var/log/app/2026-06-06.log",
    "cache hit ratio 0.98 over 10000 requests",
];

#[test]
fn clean_log_lines_are_untouched_by_default_detectors() {
    let redactor = Redactor::new();
    let mut changed = Vec::new();

    for line in CLEAN_LOG {
        let cleaned = redactor.clean(line);
        if &cleaned != line {
            changed.push(format!("  {line:?}\n    -> {cleaned:?}"));
        }
    }

    assert!(
        changed.is_empty(),
        "{} clean log line(s) were modified:\n{}",
        changed.len(),
        changed.join("\n")
    );
}

#[test]
fn clean_log_lines_are_untouched_with_phone_detector_enabled() {
    // The opt-in phone detector is the most false-positive-prone built-in;
    // it must still leave ordinary timestamped logs alone.
    let redactor = Redactor::new().with_detector(PhoneNumber);
    let mut changed = Vec::new();

    for line in CLEAN_LOG {
        let cleaned = redactor.clean(line);
        if &cleaned != line {
            changed.push(format!("  {line:?}\n    -> {cleaned:?}"));
        }
    }

    assert!(
        changed.is_empty(),
        "{} clean log line(s) were modified with phone enabled:\n{}",
        changed.len(),
        changed.join("\n")
    );
}

#[test]
fn real_phone_numbers_still_match_when_enabled() {
    // Tightening must not silence genuine phone numbers.
    let redactor = Redactor::new().with_detector(PhoneNumber);
    for input in [
        "call +1 (415) 555-0132 now",
        "415-555-0132",
        "+44 20 7946 0958",
        "+1-415-555-0132",
        "(415) 555-0132",
        "+420 123 456 789",
    ] {
        let cleaned = redactor.clean(input);
        assert!(
            cleaned.contains("[REDACTED:PHONE]"),
            "phone not detected in {input:?} -> {cleaned:?}"
        );
    }
}

/// Documents a **known, accepted limitation** rather than asserting a fix.
///
/// Luhn is a single check digit, so roughly one in ten bare 13-19 digit runs
/// passes it by chance. A 14-digit timestamp such as `20260606120000` is a real
/// example. Narrowing this would mean requiring known issuer prefixes, which
/// would miss valid non-issuer PANs -- a detection-policy change, deliberately
/// out of scope for the 0.7.0 hardening release. See README "Security model and
/// limitations".
#[test]
fn documented_limitation_long_digit_runs_may_pass_luhn() {
    let redactor = Redactor::new();
    let coincidental = "schema version 20260606120000 applied";
    assert!(
        redactor
            .clean(coincidental)
            .contains("[REDACTED:CREDIT_CARD]"),
        "if this ever stops matching, the limitation note can be removed"
    );
}

#[test]
fn phone_is_not_enabled_by_default() {
    // Documented behaviour change in 0.7.0: opt-in, like HighEntropy.
    let redactor = Redactor::new();
    let input = "call +1 (415) 555-0132 now";
    assert_eq!(redactor.clean(input), input);
    assert!(!redactor.is_dirty(input));
}
