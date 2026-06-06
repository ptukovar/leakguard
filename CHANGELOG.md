# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ptukovar/leakguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ptukovar/leakguard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.0
