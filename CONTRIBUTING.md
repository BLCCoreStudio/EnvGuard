# Contributing to EnvGuard

Thanks for helping improve EnvGuard.

## Development setup

EnvGuard currently requires Rust 1.74 or newer and has no third-party Rust dependencies.

```bash
git clone https://github.com/BLCCoreStudio/EnvGuard.git
cd EnvGuard
cargo test
```

Before opening a pull request, run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
git diff --check
```

## Detection changes

Secret detection is a balance between catching useful signals and avoiding noisy false positives. Detection-rule changes should include focused tests for both the positive case and at least one realistic non-secret or placeholder case.

Do not add real credentials, live tokens, private keys, or copied customer data to fixtures, examples, issues, or pull requests. Synthetic test values should be constructed so they cannot authenticate anywhere.

## Pull requests

Keep changes focused and explain user-visible behavior. Add or update tests when behavior is testable without external services.

Do not add telemetry, analytics, silent network communication, automatic uploads, credential collection, or remote command execution.

## Issues

For bugs, include your operating system, EnvGuard version or commit, the command used, expected behavior, and actual behavior. Redact secrets and sensitive paths before posting logs publicly.

Security vulnerabilities should not be reported in public issues. See [SECURITY.md](SECURITY.md).
