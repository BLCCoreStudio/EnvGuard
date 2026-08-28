# EnvGuard

**Catch secrets and sensitive files before they reach Git.**

EnvGuard is a small open-source CLI for catching obvious credential leaks before a commit or publish step. It scans local files or the exact blobs currently staged in Git and reports suspicious filenames and secret-like content.

```bash
envguard .
envguard --staged
```

## Why EnvGuard?

Accidentally committing a real `.env` file, private key, access token, or password can turn into an incident quickly. EnvGuard is intentionally small enough to run locally as one extra check before code leaves your machine.

The current v0.1.0 source detects a focused set of signals:

- real `.env`-style filenames while allowing common example/template variants
- common SSH private-key filenames
- PKCS#12 key-store filenames
- private-key material markers in text files
- several common provider token-prefix shapes
- AWS access-key ID shapes
- non-placeholder assignments to sensitive-looking variable names

EnvGuard skips common generated directories such as `.git`, `target`, `node_modules`, virtual environments, `dist`, and `build`. Symlinks are not followed.

## Status

EnvGuard is in early development. The v0.1.0 source is available for testing, but no GitHub Release has been published yet.

This is a heuristic guardrail, **not a guarantee that a repository contains no secrets**. It should complement provider-side secret scanning, code review, least-privilege credentials, and secret rotation practices.

## Build from source

Requirements:

- Rust 1.74 or newer
- Git for `--staged` mode

```bash
git clone https://github.com/BLCCoreStudio/EnvGuard.git
cd EnvGuard
cargo build --release
./target/release/envguard --version
```

EnvGuard has no third-party Rust dependencies in v0.1.0.

## Usage

```text
envguard [PATH]
envguard --staged
```

`envguard PATH` recursively scans files beneath a path. `envguard --staged` asks Git for the currently staged files and scans the exact staged blob contents rather than the potentially different working-tree copies.

Exit codes:

```text
0  no findings
1  potential secret or sensitive file found
2  usage or scan error
```

## Pre-commit usage

Build EnvGuard and put the binary on your `PATH`, then a minimal Git pre-commit hook can run:

```sh
#!/bin/sh
envguard --staged
```

If EnvGuard finds a potential issue, exit code `1` stops the commit so you can review the finding first.

## What EnvGuard does not do

The first release does not claim exhaustive secret detection, entropy scoring, Git-history scanning, remote repository scanning, automatic credential revocation, or provider API verification. Those are deliberately outside the initial scope.

## Security and privacy

EnvGuard runs locally. It has no telemetry, account system, network client, remote backend, or automatic upload behavior.

Findings show the file, line number when available, rule identifier, and a short explanation. EnvGuard does not print the detected secret value itself.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, focused detection improvements, false-positive reductions, tests, and portability work are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

EnvGuard is open source under the [MIT License](LICENSE).

Built by **BLC Core Studio**.
