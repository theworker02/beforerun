package beforerun

import (
	"sort"
	"strconv"
)

// SeverityChange records a finding whose severity changed between scans.
type SeverityChange struct {
	Before Finding `json:"before"`
	After  Finding `json:"after"`
}

// Delta describes the security difference between two scan summaries.
type Delta struct {
	Added          []Finding        `json:"added"`
	Resolved       []Finding        `json:"resolved"`
	Escalated      []SeverityChange `json:"escalated"`
	Deescalated    []SeverityChange `json:"deescalated"`
	RiskScoreDelta int              `json:"risk_score_delta"`
}

// Compare returns a deterministic delta between previous and current scans.
// Finding identity is based on rule, repository-relative path, line, and message.
func Compare(previous, current Summary) Delta {
	before := indexFindings(previous.Findings)
	after := indexFindings(current.Findings)
	delta := Delta{RiskScoreDelta: current.RiskScore - previous.RiskScore}

	for key, finding := range after {
		old, exists := before[key]
		if !exists {
			delta.Added = append(delta.Added, finding)
			continue
		}
		if finding.Severity > old.Severity {
			delta.Escalated = append(delta.Escalated, SeverityChange{Before: old, After: finding})
		} else if finding.Severity < old.Severity {
			delta.Deescalated = append(delta.Deescalated, SeverityChange{Before: old, After: finding})
		}
	}
	for key, finding := range before {
		if _, exists := after[key]; !exists {
			delta.Resolved = append(delta.Resolved, finding)
		}
	}

	sortFindings(delta.Added)
	sortFindings(delta.Resolved)
	sort.Slice(delta.Escalated, func(i, j int) bool { return findingKey(delta.Escalated[i].After) < findingKey(delta.Escalated[j].After) })
	sort.Slice(delta.Deescalated, func(i, j int) bool { return findingKey(delta.Deescalated[i].After) < findingKey(delta.Deescalated[j].After) })
	return delta
}

// Clean reports whether the current scan introduced no findings or severity changes.
func (d Delta) Clean() bool {
	return len(d.Added) == 0 && len(d.Escalated) == 0 && len(d.Deescalated) == 0 && len(d.Resolved) == 0
}

// IntroducesAt reports whether the delta adds or escalates a finding at or above threshold.
func (d Delta) IntroducesAt(threshold Severity) bool {
	for _, finding := range d.Added {
		if finding.Severity >= threshold {
			return true
		}
	}
	for _, change := range d.Escalated {
		if change.After.Severity >= threshold {
			return true
		}
	}
	return false
}

func indexFindings(findings []Finding) map[string]Finding {
	result := make(map[string]Finding, len(findings))
	for _, finding := range findings {
		result[findingKey(finding)] = finding
	}
	return result
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool { return findingKey(findings[i]) < findingKey(findings[j]) })
}

func findingKey(finding Finding) string {
	return finding.Rule + "\x00" + finding.Path + "\x00" + strconv.Itoa(finding.Line) + "\x00" + finding.Message
}
