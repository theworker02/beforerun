package model

import "strings"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func ParseSeverity(value string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info":
		return SeverityInfo, true
	case "low":
		return SeverityLow, true
	case "medium":
		return SeverityMedium, true
	case "high":
		return SeverityHigh, true
	case "critical":
		return SeverityCritical, true
	default:
		return SeverityInfo, false
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

func (s Severity) Weight() int {
	switch s {
	case SeverityLow:
		return 3
	case SeverityMedium:
		return 8
	case SeverityHigh:
		return 18
	case SeverityCritical:
		return 35
	default:
		return 0
	}
}

type Finding struct {
	Rule         string   `json:"rule"`
	Severity     Severity `json:"-"`
	SeverityText string   `json:"severity"`
	Path         string   `json:"path"`
	Line         int      `json:"line,omitempty"`
	Message      string   `json:"message"`
	Evidence     string   `json:"evidence,omitempty"`
	Remediation  string   `json:"remediation"`
}

func NewFinding(rule string, severity Severity, path string, line int, message, evidence, remediation string) Finding {
	return Finding{
		Rule:         rule,
		Severity:     severity,
		SeverityText: severity.String(),
		Path:         path,
		Line:         line,
		Message:      message,
		Evidence:     evidence,
		Remediation:  remediation,
	}
}

type Summary struct {
	Root         string         `json:"root"`
	FilesScanned int            `json:"files_scanned"`
	BytesScanned int64          `json:"bytes_scanned"`
	Findings     []Finding      `json:"findings"`
	Counts       map[string]int `json:"counts"`
	RiskScore    int            `json:"risk_score"`
	RiskLevel    string         `json:"risk_level"`
	Threshold    string         `json:"threshold"`
	ThresholdMet bool           `json:"threshold_met"`
	ScanErrors   []string       `json:"scan_errors,omitempty"`
}
