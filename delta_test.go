package beforerun

import "testing"

func TestCompare(t *testing.T) {
	oldDownload := finding("BR006", SeverityMedium, "install.sh", 3, "remote download executes")
	newDownload := finding("BR006", SeverityHigh, "install.sh", 3, "remote download executes")
	resolved := finding("BR003", SeverityLow, ".vscode/tasks.json", 1, "automatic task")
	added := finding("BR010", SeverityCritical, "payload.exe", 0, "committed executable")

	delta := Compare(
		Summary{Findings: []Finding{oldDownload, resolved}, RiskScore: 11},
		Summary{Findings: []Finding{newDownload, added}, RiskScore: 53},
	)

	if len(delta.Added) != 1 || delta.Added[0].Rule != "BR010" {
		t.Fatalf("unexpected added findings: %#v", delta.Added)
	}
	if len(delta.Resolved) != 1 || delta.Resolved[0].Rule != "BR003" {
		t.Fatalf("unexpected resolved findings: %#v", delta.Resolved)
	}
	if len(delta.Escalated) != 1 || delta.Escalated[0].After.Severity != SeverityHigh {
		t.Fatalf("unexpected escalations: %#v", delta.Escalated)
	}
	if delta.RiskScoreDelta != 42 {
		t.Fatalf("risk score delta = %d, want 42", delta.RiskScoreDelta)
	}
	if !delta.IntroducesAt(SeverityCritical) {
		t.Fatal("critical addition did not trigger threshold")
	}
	if delta.Clean() {
		t.Fatal("non-empty delta reported clean")
	}
}

func TestCompareClean(t *testing.T) {
	finding := finding("BR001", SeverityInfo, "README.md", 1, "example")
	delta := Compare(Summary{Findings: []Finding{finding}}, Summary{Findings: []Finding{finding}})
	if !delta.Clean() {
		t.Fatalf("identical scans produced %#v", delta)
	}
	if delta.IntroducesAt(SeverityInfo) {
		t.Fatal("identical scans introduced a finding")
	}
}

func finding(rule string, severity Severity, path string, line int, message string) Finding {
	return Finding{Rule: rule, Severity: severity, SeverityText: severity.String(), Path: path, Line: line, Message: message}
}
