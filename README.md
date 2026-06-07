<div align="center">

# leakguard

**Fast, zero-dependency redaction of secrets & PII from text and logs — in pure Rust.**

[![Crates.io](https://img.shields.io/crates/v/leakguard.svg)](https://crates.io/crates/leakguard)
[![Docs.rs](https://docs.rs/leakguard/badge.svg)](https://docs.rs/leakguard)
[![CI](https://github.com/ptukovar/leakguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ptukovar/leakguard/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![No deps](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#why-leakguard)

</div>

`leakguard` finds and removes sensitive data — emails, credit cards, IP addresses,
JWTs, SSNs, MAC addresses, AWS keys, and URLs with embedded credentials — from
arbitrary strings and log lines. It's a **library and a CLI**.

```rust
use leakguard::Redactor;

let s = Redactor::new();
let clean = s.clean("Contact alice@example.com from 10.0.0.1");
assert_eq!(clean, "Contact [REDACTED:EMAIL] from [REDACTED:IPV4]");
```

## Why leakguard?

The Rust ecosystem has crypto, parsers, and web frameworks — but no small,
**maintained, dependency-free** library for the everyday job of *not leaking PII
and secrets into your logs*. Python has `scrubadub`, JS has `redact-pii`. leakguard
fills that gap with:

- **Zero dependencies.** No `regex`, no `lazy_static`, nothing. Just `core` +
  `alloc`. Tiny build, tiny binary, fast compile.
- **`#![no_std]` friendly.** Works in embedded / WASM with `default-features = false`.
- **`#![forbid(unsafe_code)]`.** 100% safe Rust.
- **Correct by construction.** Match offsets always land on UTF-8 boundaries,
  Luhn-validated card numbers, range-checked IP octets — fewer false positives.
- **Extensible.** Plug in your own detectors with a closure.
- **Batteries included.** A `leakguard` CLI you can pipe logs through.

## Install

```toml
# Library
[dependencies]
leakguard = "0.3.0"
```

```sh
# CLI
cargo install leakguard
```

## Library usage

### Pick a masking strategy

```rust
use leakguard::{Redactor, Mask};

// [REDACTED:EMAIL]  (default)
Redactor::new();

// fixed string, from either a literal or a runtime String
Redactor::new().mask(Mask::fixed("***"));
Redactor::new().mask(Mask::fixed(String::from("***")));

// keep the last 4 chars: 4111 1111 1111 1111 -> ***************1111
Redactor::new().mask(Mask::Partial { keep_last: 4, ch: '*' });

// stable non-cryptographic fingerprint for correlation (not anonymization)
Redactor::new().mask(Mask::Hash);
```

### Pick what to detect

```rust
use leakguard::{Redactor, Kind};

let s = Redactor::only(&[Kind::Email, Kind::CreditCard]);
let s = Redactor::new().without(&Kind::IpV4); // everything except IPv4
```

### Inspect without mutating

```rust
use leakguard::Redactor;

let s = Redactor::new();
for m in s.find("email a@b.com ip 10.0.0.1") {
    println!("{} at {}..{}", m.kind, m.start, m.end);
}
assert!(s.is_dirty("token AKIAIOSFODNN7EXAMPLE"));
```

### Add a custom detector

```rust
use leakguard::{Redactor, Kind, FnDetector, Match};

let tickets = FnDetector::new(Kind::Custom("TICKET"), |input, out| {
    let mut from = 0;
    while let Some(i) = input[from..].find("JIRA-") {
        let start = from + i;
        let mut end = start + 5;
        let b = input.as_bytes();
        while end < b.len() && b[end].is_ascii_digit() { end += 1; }
        out.push(Match::new(Kind::Custom("TICKET"), start, end));
        from = end;
    }
});

let s = Redactor::new().with_detector(tickets);
assert_eq!(s.clean("see JIRA-1234"), "see [REDACTED:TICKET]");
```

## CLI usage

```sh
# Pipe a live log through it
tail -f app.log | leakguard

# Redact a file to stdout, keeping last 4 chars
leakguard --mask partial --keep 4 access.log > clean.log

# Only redact emails and IPv4, masking with '#'
leakguard --only email,ipv4 --mask char --char '#' < input.txt

# Redact everything except phone numbers
leakguard --without phone app.log

# Print supported detector names
leakguard --list-kinds

# CI guard: fail the build if a file contains secrets; print kinds/offsets to stderr
leakguard --check --verbose secrets-scan.txt || echo "found sensitive data!"
```

## Detectors

| Kind              | Example                                  | Notes                              |
|-------------------|------------------------------------------|------------------------------------|
| `Email`           | `alice@example.com`                       | requires a real-looking TLD        |
| `CreditCard`      | `4111 1111 1111 1111`                     | **Luhn-validated**, 13–19 digits   |
| `IpV4`            | `192.168.0.1`                            | each octet range-checked 0–255     |
| `IpV6`            | `2001:db8::1`                            | supports `::` compression          |
| `Jwt`             | `eyJ….eyJ….sig`                          | three base64url segments           |
| `UsSsn`           | `123-45-6789`                            | rejects invalid area numbers       |
| `MacAddress`      | `00:1A:2B:3C:4D:5E`                       | `:` or `-` separators              |
| `AwsAccessKey`    | `AKIAIOSFODNN7EXAMPLE`                    | AKIA/ASIA/… + 16 chars             |
| `UrlCredentials`  | `https://user:pass@host`                 | redacts the `user:pass` userinfo   |
| `PhoneNumber`     | `+1 (415) 555-0132`                       | conservative; needs grouping/`+`   |
| `GitHubToken`     | `ghp_…`, `github_pat_…`                   | PAT / OAuth / app / refresh        |
| `SlackToken`      | `xoxb-…`, `xoxp-…`                        | bot / user / app tokens            |
| `StripeKey`       | `sk_live_…`, `pk_test_…`                  | secret / restricted / publishable  |
| `GoogleApiKey`    | `AIza…` (39 chars)                        | fixed-length token                 |
| `OpenAiKey`       | `sk-…`, `sk-proj-…`                       | hyphenated form (≠ Stripe `sk_`)   |
| `PrivateKey`      | `-----BEGIN … PRIVATE KEY-----`           | whole PEM block, incl. body        |
| `Iban`            | `DE89370400440532013000`                  | **mod-97 checksum-validated**      |
| `GenericSecret`   | high-entropy tokens                       | **opt-in** `HighEntropy` detector  |
| `Custom(&str)`    | anything you want                        | via `FnDetector`                   |

> `GenericSecret` (the `HighEntropy` detector) is **not** in the defaults — it's
> the most false-positive-prone, so you enable it explicitly:
>
> ```rust
> use leakguard::{Redactor, detectors::HighEntropy};
> let s = Redactor::new().with_detector(HighEntropy::default());
> // or tune it: HighEntropy::new(/* min_len */ 24, /* min_entropy bits */ 4.0)
> ```

## Performance

leakguard uses hand-written, single-pass byte scanners — no regex backtracking.
Detection is roughly linear in input size. Run the bundled example:

```sh
cargo run --example redact_logs
```

## `no_std`

```toml
[dependencies]
leakguard = { version = "0.1", default-features = false }
```

This drops the CLI and `std`-only conveniences but keeps the full detection and
redaction API (it needs `alloc`).

## Contributing

Issues and PRs welcome — especially new detectors and false-positive reports
with sample inputs. Run `cargo test && cargo clippy --all-targets -- -D warnings`
before submitting.

## Author

Created and maintained by [ptukovar](https://github.com/ptukovar).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
