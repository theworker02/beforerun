# Changelog

All notable changes to BeforeRun are documented here.

## v1.0.0 — 2026-08-04

### Added

- Zero-dependency repository security scanner written in Go.
- Public `github.com/theworker02/beforerun` package API.
- `beforerun` CLI with text and JSON output.
- Severity thresholds and deterministic exit codes.
- Eleven detection rules covering package hooks, editor automation, dev containers, remote shell execution, PowerShell, credentials, Unicode deception, submodules, binary artifacts, executable scripts, and escaping symlinks.
- `.beforerunignore` support and generated-directory defaults.
- Race-enabled tests, vet, formatting checks, build verification, and self-scanning CI.
- Windows, Linux, and macOS release builds for AMD64 and ARM64.
- BeforeRun shield mark, wordmark, and package-level branding.
- MIT license, security policy, contribution guide, rule reference, and branding guide.
