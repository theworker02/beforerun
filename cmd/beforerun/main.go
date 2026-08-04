package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
		case "scan":
			args = args[1:]
		}
	}

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

	ignoreFileValues, err := scanner.ReadIgnoreFile(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read .beforerunignore: %v\n", err)
		return 2
	}
	ignores := append([]string{}, ignoreFileValues...)
	if strings.TrimSpace(*ignore) != "" {
		ignores = append(ignores, strings.Split(*ignore, ",")...)
	}

	summary, err := scanner.Scan(root, scanner.Options{Threshold: threshold, Ignores: ignores})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}
	if !*quiet {
		if *format == "json" {
			err = report.WriteJSON(os.Stdout, summary)
		} else {
			err = report.WriteText(os.Stdout, summary)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			return 2
		}
	}
	if summary.ThresholdMet {
		return 1
	}
	return 0
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
  %s version

Flags:
  --format text|json       Output format (default text)
  --fail-on severity       Blocking threshold (default high)
  --ignore paths           Additional comma-separated ignored paths
  --quiet                  Emit no report; return only an exit code

Exit codes:
  0  No finding met the threshold
  1  One or more findings met the threshold
  2  Invalid arguments or scan failure
`, name, name, name)
}
