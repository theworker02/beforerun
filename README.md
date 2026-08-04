# BeforeRun

**Inspect a repository before the repository inspects your machine.**

BeforeRun is a zero-dependency Go CLI that scans an unfamiliar codebase before you install dependencies, open automated workspace tasks, build a dev container, or execute project scripts.

It focuses on *execution surfaces* that ordinary linters often ignore: package lifecycle hooks, editor automation, remote scripts piped to shells, encoded PowerShell, committed credentials, executable artifacts, escaping symlinks, suspicious submodules, and Unicode source deception.

## Why BeforeRun?

Cloning source code is usually passive. The next click or command often is not:

- `npm install` can run lifecycle scripts.
- Opening a trusted editor workspace can expose automatic tasks and terminal overrides.
- Dev containers can run initialization and post-create hooks.
- Build scripts can download and execute remote content.
- Repositories can include binaries, private keys, or symlinks that leave the project root.

BeforeRun gives you a fast, local report before those execution paths are activated. It never executes project code and does not upload repository contents.

## Install

```bash
go install github.com/theworker02/beforerun/cmd/beforerun@latest
```

Or build from source:

```bash
git clone https://github.com/theworker02/beforerun.git
cd beforerun
go build -o beforerun ./cmd/beforerun
```

## Usage

```bash
# Scan the current directory
beforerun scan .

# Block on medium-or-higher findings
beforerun scan . --fail-on medium

# Machine-readable output
beforerun scan ./untrusted-repo --format json

# Ignore generated or organization-specific paths
beforerun scan . --ignore fixtures,third_party/cache
```

Example output:

```text
BeforeRun BLOCK — risk 53/100 (HIGH)
Scanned 29 files (184.2 KiB) in /work/untrusted-repo
Findings: 1 critical, 1 high, 0 medium, 0 low | fail-on=high

[CRITICAL] BR004 scripts/install.sh:7
  remote content is piped directly into a command shell
  Evidence: curl https://example.invalid/install.sh | bash
  Fix: Download the content separately, verify its source and checksum, then inspect it before execution.
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding met the configured threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid arguments or scan failure |

This makes BeforeRun suitable for pre-commit checks, CI jobs, download sandboxes, package review queues, and internal repository intake workflows.

## Detection rules

| Rule | Detects | Default severity |
| --- | --- | --- |
| `BR001` | Automatic package lifecycle scripts | Medium–High |
| `BR002` | VS Code folder-open tasks and terminal overrides | Medium–High |
| `BR003` | Dev container command hooks | Medium |
| `BR004` | Remote content piped directly to a shell | Critical |
| `BR005` | Dynamic or encoded PowerShell execution | High–Critical |
| `BR006` | Possible committed credentials/private keys | High–Critical |
| `BR007` | Bidirectional Unicode source controls | High |
| `BR008` | Local or relative Git submodule URLs | High |
| `BR009` | Executable and dynamic binary artifacts | Medium–High |
| `BR010` | Executable script files | Low |
| `BR011` | Symlinks escaping the repository root | High |

See [docs/rules.md](docs/rules.md) for rationale and remediation guidance.

## Ignore file

Create `.beforerunignore` in the scan root. Each non-empty line is a repository-relative path prefix. Lines beginning with `#` are comments.

```text
# Known test fixtures
internal/testdata
examples/expected-binaries
```

BeforeRun ignores common generated directories by default, including `.git`, `node_modules`, `vendor`, `dist`, `build`, `.next`, `.turbo`, and `coverage`.

## CI

```yaml
- name: Scan repository execution surfaces
  run: go run ./cmd/beforerun scan . --fail-on high
```

## Security model

BeforeRun is a fast static intake scanner, not a malware sandbox and not proof that a repository is safe. A clean report means no enabled rule matched the inspected files. Continue to review provenance, dependencies, signatures, and high-impact scripts.

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/beforerun
```

## License

MIT
