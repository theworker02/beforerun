# Baseline-aware scans

BeforeRun v1.1.0 can compare two `Summary` values without rescanning or executing repository content.

```go
previous, err := beforerun.Scan("./checkout-before", beforerun.Options{Threshold: beforerun.SeverityHigh})
if err != nil {
    log.Fatal(err)
}
current, err := beforerun.Scan("./checkout-after", beforerun.Options{Threshold: beforerun.SeverityHigh})
if err != nil {
    log.Fatal(err)
}

delta := beforerun.Compare(previous, current)
if delta.IntroducesAt(beforerun.SeverityHigh) {
    log.Fatal("the change introduces high-severity repository risk")
}
```

`Delta` reports:

- findings added by the current scan;
- findings resolved since the previous scan;
- severity escalations and de-escalations;
- the risk-score difference;
- whether new or escalated findings cross a typed severity threshold.

Finding identity uses the stable rule ID, repository-relative path, source line, and message. Results are sorted deterministically for clean CI output and reproducible JSON.
