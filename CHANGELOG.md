# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1] - 2026-09-01

### Fixed
- MSRV 1.70.0 clippy::box-default lint with Box::<HighEntropy>::default()
- cargo fmt formatting drift on CI

## [0.9.0] - 2026-09-01

### Added
- `GenericSecret` detector (opt-in `HighEntropy`), accessible via
  `Kind::GenericSecret`, `Redactor::only(&[Kind::GenericSecret])`, and CLI
  `--only generic_secret`. The detector uses a byte-level Shannon-entropy
  heuristic over sliding windows, configurable through
  `HighEntropy::new(min_len, min_entropy)`.
- Fuzz-style invariant tests covering every built-in detector under every
  mask: span validity, UTF-8 boundary safety, sorted non-overlapping outputs,
  mask reconstruction correctness, and `clean` convergence (idempotence or
  fixed-point within a bounded number of passes).
- Adversarial input tests for every detector (empty, 1-byte, boundary, CRLF,
  NUL, digit-adjacency, repeated-prefix runs) — none panic or emit invalid
  offsets.
- `--redact-literal KIND:CUSTOM` syntax for custom kind labels on the CLI
  (`--redact-literal AcmeCorp:CLIENT` -> `[REDACTED:CLIENT]`).
- Performance gate benchmarks in `examples/bench.rs`: serial and parallel
  throughput printed against the v0.8.1 baselines.

### Changed
- **`Mask::Hash` separator changed from `:` to `#`.** The 0.8.x
  `[LABEL:hhhhhhhh]` form could be re-detected as `UrlCredentials` when
  followed by `@host` (e.g. `[EMAIL:3f2a91c8]@example.com`). The new
  `[LABEL#hhhhhhhh]` uses `#`, which is never a valid secret body character
  and terminates a URL authority, making `clean` idempotent under `Mask::Hash`.
  **Migration:** consumers that parse `[LABEL:hhhhhhhh]` from `Mask::Hash`
  output must update their parsers to expect `[LABEL#hhhhhhhh]`.
- `Redactor::clean_iter` now accepts `AsRef<str>` (both `&str` and `String`
  inputs) instead of requiring `std::fmt::Display`.
- `all_detectors()` now includes `HighEntropy`, so `Redactor::only` and CLI
  `--only generic_secret` select a working scanner.
- Help text and exit-code documentation improved.
- PrivateKey moved to first priority in `default_detectors()` to prevent
  PEM-block body from being claimed by another detector.

### Fixed
- **Five quadratic bugs:**
  - `TelegramToken` no longer re-scans the token body for every leading digit.
  - `scan_prefixed_any` (`GitHubToken` / `OpenAiKey`) advances past matches
    instead of re-triggering after every byte.
  - `Iban` no longer re-scans the same run from the same start.
  - `PrivateKey` no longer re-scans the entire assembled block on every line.
- CLI unterminated PEM-block buffer now has explicit caps (1 MiB / 10 000
  lines) to prevent unbounded memory growth.

### API Freeze
This is the last minor release before 1.0.0. The public API is frozen after
0.9.0:
- `Mask` is `#[non_exhaustive]` - match arms must include a wildcard.
- `Kind` is `#[non_exhaustive]` - match arms must include a wildcard.
- The `Detector` trait uses `&self` detection; `FnDetector` signature is stable.
- No new default-on detectors will be added in 0.9.x patch releases.
- CLI flag names, JSON field names, and exit codes are stable.

## [0.8.1] - 2026-08-11

### Changed
- Multi-prefix token detectors now scan once per kind with a first-byte pre-filter
  (`possible_start[256]`), replacing 20 full-input passes with 4: `GitHubToken`
  (6 → 1), `SlackToken` (6 → 1), `StripeKey` (6 → 1), `OpenAiKey` (2 → 1).
  Synthetic 8 MiB clean JSON on Xeon 8488C (PR #4): full credential set serial
  17.6 → 93.4 MiB/s, parallel 70.8 → 316.5 MiB/s, four callers 172.4 → 552.2 MiB/s;
  per-detector GitHub 64.9 → 2,275.9 MiB/s, Slack 65.0 → 2,326.8 MiB/s,
  Stripe 63.6 → 2,237.4 MiB/s, OpenAI 189.7 → 2,339.3 MiB/s.

### Added
- Synthetic coverage for every multi-prefix variant (20 fixtures: `github_pat_`,
  `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xoxs-`/`xoxo-`,
  `sk_live_`/`sk_test_`/`rk_live_`/`rk_test_`/`pk_live_`/`pk_test_`, `sk-proj-`/`sk-`)
  in `every_multi_prefix_token_variant_is_detected` to prevent regressions.

## [0.8.0] - 2026-07-31

### Added
- Opt-in, zero-dependency `parallel` feature with `Redactor::find_parallel` and `Redactor::clean_parallel` for detector-level parallelism on large inputs.
- Allowlist and ignore rules with `Redactor::ignore`, `Redactor::ignore_list`, and `Redactor::is_ignored`, plus CLI flags `--ignore <LIST>` and `--ignore-file <FILE>` to skip allowlisted strings without redacting them.
- Literal keyword and phrase redaction with `Redactor::redact_literal` and `Redactor::redact_words`, plus CLI flags `--redact-word <WORD>`, `--redact-literal <WORD:KIND>`, and `--redact-words-file <FILE>` to redact custom literal terms without writing detector code.
- `Mask::Template` (and `Mask::template("<{LABEL}>")`) to format redaction tags using `{LABEL}` / `{label}` / `{KIND}` / `{kind}` placeholders, plus CLI `--mask template --template "<{LABEL}>"`.
- Match line and column tracking with `LocatedMatch` and `Redactor::find_located` (`Redactor::find_located_parallel`), reporting 1-indexed line numbers and UTF-8 character column offsets.
- CLI `--json` output and `--check --verbose` output now include 1-indexed line numbers (`line`) and column offsets (`column`) for every finding.
- Redaction statistics and reporting with `RedactionStats`, `Redactor::stats`, and `Redactor::clean_with_stats` (`clean_iter_with_stats`), plus CLI `--stats` / `--summary` to print a structured summary table of redacted matches to stderr.

### Fixed
- Quadratic overlap-resolution behavior on inputs with many matches from multiple detectors.

## [0.7.0] - 2026-07-27

### Fixed
- `CreditCard` detector no longer skips a card that follows a digit and a separator, such as `qty 7 4111 1111 1111 1111` or `id 9-4111111111111111`.
- `Mask::Partial` no longer returns the matched value unchanged when `keep_last` reaches the match length; `keep_last` is now clamped to at most half the match.
- `TelegramToken` detector no longer misses the shortest valid token when it ends the input.
- Prefix-based detectors now match after a digit, `-`, or `_`, so tokens such as `v2AKIAIOSFODNN7EXAMPLE` and `id42ghp_...` are redacted.
- `Email` detector now covers non-ASCII local parts instead of leaving a leading fragment in the output.
- `UrlCredentials` no longer scans to end of input for every `://`; 1 MiB of `a://` took 14 s and now takes 4 ms.
- CLI no longer re-scans the whole buffered block for each line following an unterminated PEM header; an 8 MB file took 507 s and now takes 0.6 s, with the buffer capped at 1 MiB or 10000 lines.
- CLI `--json` now emits one compact object per line (NDJSON) instead of concatenated multi-line objects that no JSON parser accepted.
- CLI `--json` no longer prints matched secret values by default, including under `--check`, where they could reach CI build logs.
- CLI JSON output now escapes control characters as `\u00XX` as required by RFC 8259.
- Overlap resolution now prefers the higher-specificity detector, so a phone number no longer shadows an adjacent JWT.

### Changed
- `PhoneNumber` is no longer enabled by default; it matched dates such as `2026-06-06 12` and corrupted ordinary log timestamps. Enable it with `Redactor::new().with_detector(PhoneNumber)`; the CLI `--only phone` and `--without phone` flags are unaffected.
- `PhoneNumber` now rejects calendar dates, matches followed by `:`, thousands-separated integers, and runs of single digits.
- `Redactor::only` can select any built-in detector, including the opt-in `PhoneNumber`.
- `is_dirty` stops at the first match instead of running every detector.

### Added
- CLI `--show-values` flag to include matched text in `--json` output.
- Bypass regression matrix in `tests/bypass.rs` covering every built-in detector across nineteen surrounding contexts.
- Clean-log fixture in `tests/false_positives.rs` asserting ordinary log output passes through unchanged.
- Sub-quadratic scaling checks in `tests/complexity.rs`, ignored by default and run with `cargo test --release --test complexity -- --ignored`.
- Release checklist in `RELEASE.md`, referenced since 0.5.0 but never added.
- README rows for the Azure, Telegram, and Discord detectors, plus notes on token boundary rules and Luhn checksum collisions.

## [0.6.1] - 2026-07-20
- Syntax fix

## [0.6.0] - 2026-07-20

### Added
- New built-in detectors:
  - Azure storage connection strings (`AZURE_CONNECTION_STRING`).
  - Telegram bot API tokens (`TELEGRAM_TOKEN`).
  - Discord bot, user, and MFA tokens (`DISCORD_TOKEN`).
- CLI `--format json` (and `--json` shortcut) option to output structured findings in JSON format.
- `Redactor::clean_iter` library helper method for batch cleaning iterators of strings.
- Integration tests covering new detectors, batch cleaning, and JSON CLI output.

## [0.5.0] - 2026-06-10

### Added
- CI matrix covering Linux, macOS, Windows, and the Rust 1.70.0 MSRV.
- Release checklist documentation in `RELEASE.md`.
- GitHub issue templates for bug reports, false positives, false negatives, and feature requests.
- Pull request template with test, detector, formatting, and no-std checklist items.
- README guidance for safely reporting detector false positives and false negatives.

## [0.4.0] - 2026-06-09

### Added
- Fuzz-style invariant tests for generated and adversarial inputs, checking UTF-8-safe match boundaries, sorted non-overlapping spans, and mask rendering.
- Dependency-free benchmark harness in `examples/bench.rs` using `std::time::Instant`.
- README security model and limitations section clarifying best-effort redaction, false positives/negatives, and `Mask::Hash` limitations.
- `SECURITY.md` with supported-version and private reporting guidance.

## [0.3.0] - 2026-06-07

### Added
- CLI `--list-kinds` option to print supported detector kind names.
- CLI `--without` / `--exclude` option to disable selected detectors from the active set.
- CLI `--check --verbose` reporting with matched kinds and offsets written to stderr without printing secret values.
- Additional CLI integration tests for file input, kind listing, excluded detectors, and verbose check output.

## [0.2.0] - 2026-06-06

### Added
- `Mask::fixed` for fixed replacement strings from either string literals or runtime `String` values.
- Regression coverage for overlong credit-card candidates and multiline PEM redaction through the CLI.

### Changed
- `Mask::Fixed` now stores `Cow<'static, str>`, giving one cleaner API for both borrowed and owned replacement strings.
- `Mask::Hash` documentation now clearly describes it as a non-cryptographic correlation fingerprint, not anonymization.

### Fixed
- CLI now preserves input line endings instead of rewriting output line-by-line.
- CLI now redacts multiline PEM private-key blocks when reading from stdin or files.
- `CreditCard` detector now rejects candidates with more than 19 digits, including grouped candidates.
- `HighEntropy` no-std entropy approximation no longer overestimates single-character/low-diversity runs.

### Removed
- Removed the temporary `Mask::FixedOwned` variant; use `Mask::fixed(value)` or `Mask::Fixed(value.into())` instead.

## [0.1.1] - 2026-06-01

### Changed
- `CreditCard` detector: replaced per-candidate `Vec` allocation with a fixed-size stack array for significantly better performance (no heap allocations in the hot path).

## [0.1.0] - 2026-05-30

### Added
- Zero-dependency, `#![forbid(unsafe_code)]`, `no_std`-friendly core.
- `Redactor` API with `clean`, `find`, `is_dirty`, and builder configuration.
- Built-in detectors: `Email`, `CreditCard` (Luhn), `IpV4`, `IpV6`, `Jwt`,
  `UsSsn`, `MacAddress`, `AwsAccessKey`, `UrlCredentials`, `PhoneNumber`,
  `GitHubToken`, `SlackToken`, `StripeKey`, `GoogleApiKey`, `OpenAiKey`,
  `PrivateKey` (PEM blocks), and `Iban` (mod-97 checksum-validated).
- Opt-in `HighEntropy` detector (`Kind::GenericSecret`) for catching unknown
  high-entropy secrets, with configurable length / entropy thresholds.
- Masking strategies: `Label`, `Fixed`, `Char`, `Partial`, `Hash`.
- Custom detectors via the `Detector` trait and `FnDetector` closure adapter.
- `leakguard` CLI for redacting stdin/files, with a `--check` mode for CI guards.
- `redact_logs` example and an integration test suite.

[Unreleased]: https://github.com/ptukovar/leakguard/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/ptukovar/leakguard/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/ptukovar/leakguard/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/ptukovar/leakguard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/ptukovar/leakguard/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ptukovar/leakguard/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/ptukovar/leakguard/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/ptukovar/leakguard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ptukovar/leakguard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ptukovar/leakguard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ptukovar/leakguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ptukovar/leakguard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.0
