# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[Unreleased]: https://github.com/ptukovar/leakguard/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/ptukovar/leakguard/releases/tag/v0.1.0