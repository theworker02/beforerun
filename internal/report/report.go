package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/theworker02/beforerun/internal/model"
)

func WriteJSON(writer io.Writer, summary model.Summary) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func WriteText(writer io.Writer, summary model.Summary) error {
	status := "PASS"
	if summary.ThresholdMet {
		status = "BLOCK"
	}
	if _, err := fmt.Fprintf(writer, "BeforeRun %s — risk %d/100 (%s)\n", status, summary.RiskScore, strings.ToUpper(summary.RiskLevel)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Scanned %d files (%s) in %s\n", summary.FilesScanned, humanBytes(summary.BytesScanned), summary.Root); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Findings: %d critical, %d high, %d medium, %d low | fail-on=%s\n\n",
		summary.Counts["critical"], summary.Counts["high"], summary.Counts["medium"], summary.Counts["low"], summary.Threshold); err != nil {
		return err
	}

	if len(summary.Findings) == 0 {
		_, err := fmt.Fprintln(writer, "No risky repository behaviors detected.")
		return err
	}
	for _, finding := range summary.Findings {
		location := finding.Path
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.Line)
		}
		if _, err := fmt.Fprintf(writer, "[%s] %s %s\n  %s\n", strings.ToUpper(finding.Severity.String()), finding.Rule, location, finding.Message); err != nil {
			return err
		}
		if finding.Evidence != "" {
			if _, err := fmt.Fprintf(writer, "  Evidence: %s\n", finding.Evidence); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(writer, "  Fix: %s\n\n", finding.Remediation); err != nil {
			return err
		}
	}
	if len(summary.ScanErrors) > 0 {
		if _, err := fmt.Fprintf(writer, "Warnings: %d files could not be fully inspected.\n", len(summary.ScanErrors)); err != nil {
			return err
		}
	}
	return nil
}

func humanBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}
