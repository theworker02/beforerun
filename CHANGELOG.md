# Changelog

All notable changes to BeforeRun are documented here.

## v1.3.0 — 2026-08-14

### Added

- `BR012` GitHub Actions privilege detection for `pull_request_target`, `workflow_run`, and `permissions: write-all`.
- Critical severity when a `pull_request_target` workflow also checks out or interpolates untrusted pull-request content.

### Compatibility

- Existing scan, compare, CLI, output, rule, and ignore behavior is unchanged.
- The release is fully additive and remains source-compatible with v1.2.0.

## v1.2.0 — 2026-08-11

### Added

- Durable baseline files with `WriteBaseline`, `ReadBaseline`, and `DiffAgainstBaseline`.
- `beforerun baseline write <path>` to capture a scan snapshot for CI.
- `beforerun baseline show <path>` to inspect stored baseline metadata and summary.
- `beforerun diff --baseline <path> [--fail-on severity]` for pull-request and CI diff gates.

### Compatibility

- Existing scan, compare, CLI, output, rule, and ignore behavior is unchanged.
- The release is fully additive and remains source-compatible with v1.1.0.

## v1.1.0 — 2026-08-04

### Added

- Public `Compare(previous, current Summary) Delta` API for baseline-aware repository security checks.
- Deterministic added and resolved finding lists.
- Severity escalation and de-escalation tracking.
- Risk-score deltas for trend reporting.
- `Delta.IntroducesAt` for pull-request and CI policy gates.
- `Delta.Clean` for exact baseline-equivalence checks.

### Compatibility

- Existing scanner, CLI, output, rule, and ignore behavior is unchanged.
- The release is fully additive and remains source-compatible with v1.0.0.

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
