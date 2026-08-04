// Package beforerun provides a reusable API for statically inspecting
// untrusted repositories before project-controlled code is executed.
package beforerun

import (
	"github.com/theworker02/beforerun/internal/model"
	"github.com/theworker02/beforerun/internal/scanner"
)

// Severity describes the impact of a finding.
type Severity = model.Severity

const (
	SeverityInfo     = model.SeverityInfo
	SeverityLow      = model.SeverityLow
	SeverityMedium   = model.SeverityMedium
	SeverityHigh     = model.SeverityHigh
	SeverityCritical = model.SeverityCritical
)

// Finding describes one detected repository risk.
type Finding = model.Finding

// Summary contains the complete result of a scan.
type Summary = model.Summary

// Options controls scan behavior.
type Options struct {
	// Threshold determines when Summary.ThresholdMet becomes true.
	Threshold Severity
	// Ignores contains repository-relative path prefixes to skip.
	Ignores []string
}

// Scan statically inspects root without executing repository content or using
// the network.
func Scan(root string, options Options) (Summary, error) {
	return scanner.Scan(root, scanner.Options{
		Threshold: options.Threshold,
		Ignores:   options.Ignores,
	})
}

// ParseSeverity converts a textual severity into its typed value.
func ParseSeverity(value string) (Severity, bool) {
	return model.ParseSeverity(value)
}

// ReadIgnoreFile parses .beforerunignore from root. A missing file is not an
// error.
func ReadIgnoreFile(root string) ([]string, error) {
	return scanner.ReadIgnoreFile(root)
}
