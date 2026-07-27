# Contributing to leakguard

Thanks for taking the time to contribute. Issues and pull requests are welcome,
especially new detectors and false-positive reports with sample inputs.

## Never post real secrets

leakguard is a tool for handling sensitive data, so reports about it often
contain the very thing that should not be shared. Use **fake or synthetic
examples only**. Do not paste real secrets, tokens, private keys, customer
data, or production logs into issues, pull requests, or discussions.

If you need a realistic example, use a well-known documentation value such as
`AKIAIOSFODNN7EXAMPLE`, the `4111 1111 1111 1111` test card, or an address in a
reserved range like `203.0.113.42`.

If you have already published a real credential anywhere, rotate it first and
treat the report as secondary.

## Reporting bugs

Use the issue templates. They exist so reports arrive with the details needed to
reproduce a problem:

- **Bug report** for crashes, panics, or incorrect behaviour.
- **False positive** for text that leakguard redacts but should leave alone.
- **False negative** for a secret leakguard should have caught but did not.
- **Feature request** for new detectors or API changes.

A good detector report includes the leakguard version, the detector kind if you
know it, the fake input, the actual output, the expected output, and whether the
issue affects the library, the CLI, or both.

## Security issues

Do not open a public issue for a vulnerability or a serious redaction bypass.
See [SECURITY.md](SECURITY.md) for the private reporting process.

A redaction bypass, where data survives `clean()` that a documented detector
should have removed, counts as a security issue rather than an ordinary bug.

## Development setup

```sh
git clone https://github.com/ptukovar/leakguard
cd leakguard
cargo test
```

There are no dependencies to install beyond a Rust toolchain.

## Before submitting a pull request

Run the same checks CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo build --no-default-features
```

CI also runs clippy on the 1.70.0 MSRV, which is stricter than recent stable in
places. If you have that toolchain installed, it is worth checking locally:

```sh
cargo +1.70.0 clippy --all-targets -- -D warnings
cargo +1.70.0 test --all-features
```

Timing-sensitive complexity checks are excluded from the default test run.
Run them on an idle machine if you touch detector scanning:

```sh
cargo test --release --test complexity -- --ignored
```

## Project constraints

These define the crate. A change that breaks one will not be merged, however
useful it is otherwise:

- **Zero dependencies**, including dev-dependencies. No `regex`, no
  `lazy_static`, no test frameworks.
- **`#![forbid(unsafe_code)]`**.
- **`no_std` compatible** with `alloc`.
- **MSRV 1.70.0.** Avoid newer standard library APIs.
- **Match offsets always land on UTF-8 character boundaries.**
- **Detection is linear in input size.** No scan may re-read to the end of the
  input for each occurrence of something. Two quadratic bugs have shipped
  before; `tests/complexity.rs` guards against a third.

## Adding a detector

Detectors live in `src/detectors.rs` and implement the `Detector` trait. Each
one is a hand-written byte scanner, so there is no regex to write.

A new detector needs:

1. A `Kind` variant in `src/types.rs` and a label in `Kind::label`.
2. The detector itself, with a doc comment showing an example.
3. Registration in `default_detectors` in `src/lib.rs`, unless it is
   false-positive-prone enough to be opt-in like `PhoneNumber` and
   `HighEntropy`.
4. CLI wiring: `KIND_NAMES`, `parse_kind`, and the `HELP` text in
   `src/bin/leakguard.rs`.
5. A row in the README detector table.
6. Tests: a canonical synthetic secret in `tests/bypass.rs`, and negatives in
   `tests/false_positives.rs` if the pattern could plausibly appear in ordinary
   text.

Two things worth thinking about before writing the scanner:

- **Boundaries.** Where does the token start and end, and what may legitimately
  precede it? Prefixed detectors accept a preceding digit, `-`, or `_`, but not
  a letter. See `bounded_left_relaxed`.
- **False positives.** A detector that fires on ordinary log output is worse
  than no detector, because it corrupts the logs people need to read. If yours
  cannot be made precise, make it opt-in.

## Style

Keep to the existing style: `cargo fmt` defaults, comments that explain *why*
rather than restating the code, and tests named after the behaviour they pin.

## Licence

By contributing you agree that your work is licensed under the same terms as the
project, MIT or Apache-2.0 at the user's option.
