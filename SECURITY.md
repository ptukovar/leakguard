# Security Policy

## Supported versions

Security fixes are provided for the latest published minor release. Please update
to the newest version before reporting an issue, unless the issue prevents you
from doing so.

## Reporting a vulnerability

If you find a security issue, a serious redaction bypass, or a case where
leakguard exposes data it claims to remove, please report it privately instead of
opening a public issue.

Preferred reporting path:

1. Use GitHub's private vulnerability reporting flow for this repository if it is
   available.
2. If private reporting is not available, contact the maintainer through GitHub
   and avoid including live secrets or sensitive production data in the first
   message.

Please include:

- The leakguard version.
- Whether the issue affects the library, CLI, or both.
- A minimal reproduction using fake/test secrets.
- Expected behavior and actual behavior.

## Scope

leakguard is a best-effort redaction tool. Reports are especially useful when
they involve:

- Panics or crashes on untrusted input.
- Invalid UTF-8 boundary offsets from detectors.
- Sensitive data remaining visible after a documented detector should redact it.
- CLI behavior that leaks data in `--check` or verbose output.

False negatives and false positives are also welcome as regular issues when they
do not involve live secrets or private data.
