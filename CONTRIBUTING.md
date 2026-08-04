# Contributing

Contributions should keep BeforeRun fast, deterministic, local-first, and safe to run against untrusted input.

## Setup

```bash
go test ./...
go vet ./...
go build ./cmd/beforerun
```

## Rule requirements

A new rule should include:

1. a stable `BRxxx` identifier;
2. a narrow threat model and low false-positive surface;
3. actionable remediation;
4. tests covering detection and a benign counterexample;
5. documentation in `docs/rules.md`.

Rules must never execute repository files, resolve network resources, install dependencies, or expose full suspected secrets in output.
