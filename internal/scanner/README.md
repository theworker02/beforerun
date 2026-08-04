<p align="center"><img src="../../assets/brand/beforerun-mark.svg" alt="BeforeRun logo" width="160"></p>

# Scanner engine

`internal/scanner` contains BeforeRun’s non-executing filesystem walker and detection rules. It reads repository content locally, skips generated directories, limits file sizes, reports scan errors without aborting the entire walk, and never resolves network resources.

Rule behavior is documented in [`docs/rules.md`](../../docs/rules.md).
