<div align="center">

# leakguard

**Fast, zero-dependency redaction of secrets & PII from text and logs — in pure Rust.**

[![Crates.io](https://img.shields.io/crates/v/leakguard.svg)](https://crates.io/crates/leakguard)
[![Docs.rs](https://docs.rs/leakguard/badge.svg)](https://docs.rs/leakguard)
[![CI](https://github.com/ptukovar/leakguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ptukovar/leakguard/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![No deps](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#why-leakguard)
![Crates.io Total Downloads](https://img.shields.io/crates/d/leakguard)


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
leakguard = "0.8.0"
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

// custom template formatting with uppercase {LABEL} or lowercase {label}
Redactor::new().mask(Mask::template("<{LABEL}:{label}>"));

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

### Allowlist safe values and redact custom words

```rust
use leakguard::{Redactor, Kind};

// Allowlist known-safe IPs or internal emails so they are not redacted
let s = Redactor::new()
    .ignore("10.0.0.1")
    .ignore_list(["test@example.com", "admin@example.com"])
    // Redact custom company names or keywords without writing a custom detector
    .redact_literal("AcmeCorp", Kind::Custom("CLIENT"))
    .redact_words(["ProjectX", "SuperSecret"], Kind::Custom("KEYWORD"));

let clean = s.clean("Contact admin@example.com at AcmeCorp from 10.0.0.1");
assert_eq!(clean, "Contact admin@example.com at [REDACTED:CLIENT] from 10.0.0.1");
```

### Get redaction statistics and line locations

```rust
use leakguard::Redactor;

let s = Redactor::new();

// Clean text while collecting summary statistics
let (clean, stats) = s.clean_with_stats("Contact alice@example.com from 10.0.0.1");
println!("{stats}");
// Prints: 2 matches (31 bytes redacted)
//           EMAIL: 1 match
//           IPV4: 1 match

// Locate matches with 1-indexed line and column numbers
for loc in s.find_located("first line\nemail alice@example.com") {
    println!("Found {} on line {}, col {}", loc.matched.kind, loc.line, loc.column);
}
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

### Redact Large Inputs in Parallel

Enable the opt-in `parallel` feature to scan large inputs across detectors with
scoped standard library threads:

```toml
[dependencies]
leakguard = { version = "0.8", features = ["parallel"] }
```

```rust
use leakguard::Redactor;

let redactor = Redactor::new();
let cleaned = redactor.clean_parallel(&large_input);
```

The parallel APIs leave one available CPU for other work and use the serial
path for inputs smaller than 256 KiB. `find_parallel` and `clean_parallel`
produce the same matches and output as their serial counterparts. Use one level
of parallelism at a time when the caller already processes multiple inputs in
parallel.

## CLI usage

```sh
# Pipe a live log through it
tail -f app.log | leakguard

# Redact a file to stdout, keeping last 4 chars
leakguard --mask partial --keep 4 access.log > clean.log

# Custom template masking with uppercase {LABEL} or lowercase {label}
leakguard --mask template --template "<{LABEL}>" access.log

# Ignore safe test IPs and internal test emails
leakguard --ignore 10.0.0.1,test@example.com app.log

# Redact custom company names or project keywords on the fly
leakguard --redact-word AcmeCorp --redact-literal "CUST-9981:CUSTOMER" app.log

# Only redact emails and IPv4, masking with '#'
leakguard --only email,ipv4 --mask char --char '#' < input.txt

# Redact everything except phone numbers
leakguard --without phone app.log

# Print redaction summary statistics to stderr after processing
leakguard --stats app.log > clean.log

# Structured findings as NDJSON (one compact object per line, including line/column)
tail -f app.log | leakguard --json

# Include the matched secret text (off by default so findings are safe to log)
leakguard --json --show-values suspect.log

# Print supported detector names
leakguard --list-kinds

# CI guard: fail the build if a file contains secrets; print kinds/offsets/line/col to stderr
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
| `GitHubToken`     | `ghp_…`, `github_pat_…`                   | PAT / OAuth / app / refresh        |
| `SlackToken`      | `xoxb-…`, `xoxp-…`                        | bot / user / app tokens            |
| `StripeKey`       | `sk_live_…`, `pk_test_…`                  | secret / restricted / publishable  |
| `GoogleApiKey`    | `AIza…` (39 chars)                        | fixed-length token                 |
| `OpenAiKey`       | `sk-…`, `sk-proj-…`                       | hyphenated form (≠ Stripe `sk_`)   |
| `PrivateKey`      | `-----BEGIN … PRIVATE KEY-----`           | whole PEM block, incl. body        |
| `Iban`            | `DE89370400440532013000`                  | **mod-97 checksum-validated**      |
| `AzureConnectionString` | `DefaultEndpointsProtocol=…;AccountKey=…` | storage connection strings   |
| `TelegramToken`   | `123456789:ABCdef…`                       | bot API token (`id:secret`)        |
| `DiscordToken`    | `mfa.…`, `MTIz….Xyz….abc…`                | bot / user / MFA tokens            |
| `PhoneNumber`     | `+1 (415) 555-0132`                       | **opt-in** since 0.7.0 (see below) |
| `GenericSecret`   | high-entropy tokens                       | **opt-in** `HighEntropy` detector  |
| `Custom(&str)`    | anything you want                        | via `FnDetector`                   |

> Two detectors are **not** in the defaults because they are the most
> false-positive-prone. Enable them explicitly:
>
> ```rust
> use leakguard::{Redactor, detectors::{HighEntropy, PhoneNumber}};
>
> // Generic high-entropy secrets.
> let s = Redactor::new().with_detector(HighEntropy::default());
> // or tune it: HighEntropy::new(/* min_len */ 24, /* min_entropy bits */ 4.0)
>
> // Phone numbers (opt-in since 0.7.0 — see CHANGELOG for the rationale).
> let s = Redactor::new().with_detector(PhoneNumber);
> ```
>
> On the CLI, `--only phone` and `--without phone` continue to work as before.


## Security model and limitations

leakguard is a **best-effort redaction tool** intended to reduce accidental
leakage of secrets and personally identifiable information in logs, text, and CI
workflows. It is not a substitute for secret management, access control, code
review, or incident response.

Important limitations:

- Detectors are intentionally conservative in several places to reduce false
  positives, so some real secrets or PII formats may not be detected.
- Some detectors can still produce false positives, especially phone numbers and
  opt-in high-entropy scanning.
- **Token boundaries.** Prefix-based detectors (`AKIA…`, `ghp_…`, `sk_live_…`,
  `AIza…`, `xoxb-…`, `eyJ…`) require the prefix to start at a token boundary. A
  preceding digit, `-`, or `_` is allowed (`v2AKIA…` and `id 9-ghp_…` are
  redacted), but a prefix embedded directly after *letters* is treated as an
  interior substring and is **not** matched — `notAIza…` is left alone. This
  keeps identifiers that merely contain a prefix from being redacted.
- **Checksum-only detectors match by chance.** `CreditCard` accepts any 13–19
  digit run passing the Luhn check, which roughly one in ten arbitrary digit
  runs does. A 14-digit timestamp such as `20260606120000` can therefore be
  redacted as a card number. Use `--without credit_card` on inputs dominated by
  long numeric identifiers.
- **Adjacent values that change meaning are not matched.** Gluing a digit onto
  a numeric secret produces a different value (`1` + `203.0.113.42` is not a
  valid IPv4 address), so such strings are deliberately left alone.
- Redaction should happen as early as possible, before sensitive data leaves your
  process or enters persistent logs.
- `Mask::Hash` is a stable, non-cryptographic fingerprint for correlation only.
  It is not anonymization and does not protect low-entropy values from guessing
  or dictionary attacks.
- Keep raw logs and unredacted inputs protected. Treat leakguard as a defense in
  depth layer, not as the only control protecting sensitive data.

If you believe you found a vulnerability or a serious redaction bypass, please
report it privately through GitHub's vulnerability reporting flow when available,
or contact the maintainer through GitHub before opening a public issue.

## Performance

leakguard uses hand-written, single-pass byte scanners — no regex backtracking.
Detection is roughly linear in input size. Run the bundled example and benchmark
harness:

```sh
cargo run --example redact_logs
cargo run --release --example bench
cargo run --release --all-features --example bench
```

The benchmark harness is intentionally dependency-free and uses
`std::time::Instant`, so run it several times on an otherwise idle machine when
comparing changes. The all-features run also compares serial and parallel
redaction on a large synthetic input.

## `no_std`

```toml
[dependencies]
leakguard = { version = "0.8", default-features = false }
```

This drops the CLI and `std`-only conveniences but keeps the full detection and
redaction API (it needs `alloc`).


## Reporting detector issues

False positives and false negatives are extremely useful for improving leakguard.
Please report them with **fake or synthetic examples only**. Do not paste real
secrets, tokens, private keys, customer data, or production logs into GitHub
issues, pull requests, or discussions.

Helpful reports usually include:

- leakguard version
- detector kind, if known
- fake input text
- actual output
- expected output
- whether the issue affects the library, CLI, or both

## Contributing

Issues and PRs welcome — especially new detectors and false-positive reports
with sample inputs. Run `cargo test && cargo clippy --all-targets -- -D warnings`
before submitting.

## Author

Created and maintained by [ptukovar](https://github.com/ptukovar).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
