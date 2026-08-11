package beforerun

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// BaselineFormatVersion is the supported on-disk baseline schema version.
const BaselineFormatVersion = 1

// Baseline is a durable scan snapshot used for CI diff gates.
type Baseline struct {
	FormatVersion int       `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`
	Summary       Summary   `json:"summary"`
}

// WriteBaseline persists summary as a versioned baseline file.
func WriteBaseline(writer io.Writer, summary Summary) error {
	baseline := Baseline{
		FormatVersion: BaselineFormatVersion,
		CreatedAt:     time.Now().UTC(),
		Summary:       summary,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(baseline)
}

// ReadBaseline loads a baseline file written by WriteBaseline.
func ReadBaseline(reader io.Reader) (Baseline, error) {
	var baseline Baseline
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return Baseline{}, fmt.Errorf("decode baseline: %w", err)
	}
	if baseline.FormatVersion != BaselineFormatVersion {
		return Baseline{}, fmt.Errorf("unsupported baseline format version %d", baseline.FormatVersion)
	}
	normalizeSummary(&baseline.Summary)
	return baseline, nil
}

// DiffAgainstBaseline scans root and compares the result with the stored baseline.
func DiffAgainstBaseline(root, path string, options Options) (Delta, Summary, error) {
	file, err := os.Open(path)
	if err != nil {
		return Delta{}, Summary{}, fmt.Errorf("open baseline: %w", err)
	}
	defer file.Close()

	baseline, err := ReadBaseline(file)
	if err != nil {
		return Delta{}, Summary{}, err
	}

	current, err := Scan(root, options)
	if err != nil {
		return Delta{}, Summary{}, err
	}
	return Compare(baseline.Summary, current), current, nil
}

func normalizeSummary(summary *Summary) {
	for index := range summary.Findings {
		finding := &summary.Findings[index]
		if finding.SeverityText == "" {
			continue
		}
		severity, ok := ParseSeverity(finding.SeverityText)
		if ok {
			finding.Severity = severity
		}
	}
}
