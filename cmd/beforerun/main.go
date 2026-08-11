package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/theworker02/beforerun"
	"github.com/theworker02/beforerun/internal/model"
	"github.com/theworker02/beforerun/internal/report"
	"github.com/theworker02/beforerun/internal/scanner"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Printf("beforerun %s\n", version)
			return 0
		case "help", "--help", "-h":
			printUsage()
			return 0
		case "baseline":
			return runBaseline(args[1:])
		case "diff":
			return runDiff(args[1:])
		case "scan":
			args = args[1:]
		}
	}
	return runScan(args)
}

func runScan(args []string) int {
	flags := flag.NewFlagSet("beforerun scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	format := flags.String("format", "text", "report format: text or json")
	failOn := flags.String("fail-on", "high", "minimum severity that blocks: info, low, medium, high, critical")
	ignore := flags.String("ignore", "", "comma-separated additional paths to ignore")
	quiet := flags.Bool("quiet", false, "suppress output; use the exit code only")
	flags.Usage = printUsage
	args = normalizeArgs(args)
	if err := flags.Parse(args); err != nil {
		return 2
	}

	threshold, ok := model.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid --fail-on value %q\n", *failOn)
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(os.Stderr, "invalid --format value %q\n", *format)
		return 2
	}

	root := "."
	if flags.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "only one scan path may be provided")
		return 2
	}
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}

	summary, err := scanRoot(root, threshold, *ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}
	if !*quiet {
		if err := writeSummary(os.Stdout, summary, *format); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			return 2
		}
	}
	if summary.ThresholdMet {
		return 1
	}
	return 0
}

func runBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: beforerun baseline <write|show> <path>")
		return 2
	}
	switch args[0] {
	case "write":
		return runBaselineWrite(args[1:])
	case "show":
		return runBaselineShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline command %q\n", args[0])
		return 2
	}
}

func runBaselineWrite(args []string) int {
	flags := flag.NewFlagSet("beforerun baseline write", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	failOn := flags.String("fail-on", "high", "scan threshold used while capturing the baseline")
	ignore := flags.String("ignore", "", "comma-separated additional paths to ignore")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: beforerun baseline write <path>")
		return 2
	}

	threshold, ok := model.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid --fail-on value %q\n", *failOn)
		return 2
	}

	root := "."
	path := flags.Arg(0)
	summary, err := scanRoot(root, threshold, *ignore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}

	file, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create baseline: %v\n", err)
		return 2
	}
	writeErr := beforerun.WriteBaseline(file, summary)
	closeErr := file.Close()
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "write baseline: %v\n", writeErr)
		return 2
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "close baseline: %v\n", closeErr)
		return 2
	}
	fmt.Fprintf(os.Stdout, "wrote baseline with %d findings to %s\n", len(summary.Findings), path)
	return 0
}

func runBaselineShow(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: beforerun baseline show <path>")
		return 2
	}

	file, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open baseline: %v\n", err)
		return 2
	}
	defer file.Close()

	baseline, err := beforerun.ReadBaseline(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read baseline: %v\n", err)
		return 2
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(baseline); err != nil {
		fmt.Fprintf(os.Stderr, "write baseline: %v\n", err)
		return 2
	}
	return 0
}

func runDiff(args []string) int {
	flags := flag.NewFlagSet("beforerun diff", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baselinePath := flags.String("baseline", "", "baseline file to compare against")
	failOn := flags.String("fail-on", "high", "minimum severity introduced by the diff that blocks")
	ignore := flags.String("ignore", "", "comma-separated additional paths to ignore")
	format := flags.String("format", "text", "report format: text or json")
	quiet := flags.Bool("quiet", false, "suppress output; use the exit code only")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *baselinePath == "" {
		fmt.Fprintln(os.Stderr, "diff requires --baseline <path>")
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(os.Stderr, "invalid --format value %q\n", *format)
		return 2
	}

	threshold, ok := model.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid --fail-on value %q\n", *failOn)
		return 2
	}

	root := "."
	if flags.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "only one scan path may be provided")
		return 2
	}
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}

	delta, current, err := beforerun.DiffAgainstBaseline(root, *baselinePath, beforerun.Options{
		Threshold: threshold,
		Ignores:   collectIgnores(root, *ignore),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "diff failed: %v\n", err)
		return 2
	}
	if !*quiet {
		if err := writeDelta(os.Stdout, delta, current, threshold, *format); err != nil {
			fmt.Fprintf(os.Stderr, "write diff: %v\n", err)
			return 2
		}
	}
	if delta.IntroducesAt(threshold) {
		return 1
	}
	return 0
}

func scanRoot(root string, threshold model.Severity, ignore string) (model.Summary, error) {
	ignoreFileValues, err := scanner.ReadIgnoreFile(root)
	if err != nil {
		return model.Summary{}, fmt.Errorf("read .beforerunignore: %w", err)
	}
	ignores := append([]string{}, ignoreFileValues...)
	if strings.TrimSpace(ignore) != "" {
		ignores = append(ignores, strings.Split(ignore, ",")...)
	}
	return scanner.Scan(root, scanner.Options{Threshold: threshold, Ignores: ignores})
}

func collectIgnores(root, ignore string) []string {
	ignoreFileValues, err := scanner.ReadIgnoreFile(root)
	if err != nil {
		return nil
	}
	ignores := append([]string{}, ignoreFileValues...)
	if strings.TrimSpace(ignore) != "" {
		ignores = append(ignores, strings.Split(ignore, ",")...)
	}
	return ignores
}

func writeSummary(writer io.Writer, summary model.Summary, format string) error {
	if format == "json" {
		return report.WriteJSON(writer, summary)
	}
	return report.WriteText(writer, summary)
}

func writeDelta(writer io.Writer, delta beforerun.Delta, summary model.Summary, threshold model.Severity, format string) error {
	if format == "json" {
		payload := struct {
			Delta   beforerun.Delta `json:"delta"`
			Current model.Summary   `json:"current"`
		}{Delta: delta, Current: summary}
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(payload)
	}

	status := "PASS"
	if delta.IntroducesAt(threshold) {
		status = "BLOCK"
	}
	if _, err := fmt.Fprintf(writer, "BeforeRun diff %s — risk delta %+d (now %d/100)\n", status, delta.RiskScoreDelta, summary.RiskScore); err != nil {
		return err
	}
	if delta.Clean() {
		_, err := fmt.Fprintln(writer, "No changes since the stored baseline.")
		return err
	}
	if len(delta.Added) > 0 {
		if _, err := fmt.Fprintf(writer, "\nAdded (%d):\n", len(delta.Added)); err != nil {
			return err
		}
		for _, finding := range delta.Added {
			if _, err := fmt.Fprintf(writer, "  [%s] %s %s\n", strings.ToUpper(finding.SeverityText), finding.Rule, finding.Path); err != nil {
				return err
			}
		}
	}
	if len(delta.Resolved) > 0 {
		if _, err := fmt.Fprintf(writer, "\nResolved (%d):\n", len(delta.Resolved)); err != nil {
			return err
		}
		for _, finding := range delta.Resolved {
			if _, err := fmt.Fprintf(writer, "  [%s] %s %s\n", strings.ToUpper(finding.SeverityText), finding.Rule, finding.Path); err != nil {
				return err
			}
		}
	}
	if len(delta.Escalated) > 0 {
		if _, err := fmt.Fprintf(writer, "\nEscalated (%d):\n", len(delta.Escalated)); err != nil {
			return err
		}
		for _, change := range delta.Escalated {
			if _, err := fmt.Fprintf(writer, "  %s %s -> %s %s\n", change.Before.SeverityText, change.Before.Rule, change.After.SeverityText, change.After.Path); err != nil {
				return err
			}
		}
	}
	if len(delta.Deescalated) > 0 {
		if _, err := fmt.Fprintf(writer, "\nDe-escalated (%d):\n", len(delta.Deescalated)); err != nil {
			return err
		}
		for _, change := range delta.Deescalated {
			if _, err := fmt.Fprintf(writer, "  %s %s -> %s %s\n", change.Before.SeverityText, change.Before.Rule, change.After.SeverityText, change.After.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeArgs(args []string) []string {
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--format=") || strings.HasPrefix(arg, "--fail-on=") || strings.HasPrefix(arg, "--ignore=") || arg == "--quiet" {
			flags = append(flags, arg)
			continue
		}
		if arg == "--format" || arg == "--fail-on" || arg == "--ignore" {
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func printUsage() {
	name := filepath.Base(os.Args[0])
	fmt.Printf(`BeforeRun scans an untrusted repository before you execute it.

Usage:
  %s scan [path] [flags]
  %s [path] [flags]
  %s baseline write <path> [flags]
  %s baseline show <path>
  %s diff --baseline <path> [path] [flags]
  %s version

Flags:
  --format text|json       Output format (default text)
  --fail-on severity       Blocking threshold (default high)
  --ignore paths           Additional comma-separated ignored paths
  --quiet                  Emit no report; return only an exit code
  --baseline path          Baseline file for diff

Exit codes:
  0  No finding met the threshold
  1  One or more findings met the threshold
  2  Invalid arguments or scan failure
`, name, name, name, name, name, name)
}
