package scanner

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/theworker02/beforerun/internal/model"
)

const maxFileSize = 2 << 20 // 2 MiB

type Options struct {
	Threshold model.Severity
	Ignores   []string
}

func Scan(root string, options Options) (model.Summary, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return model.Summary{}, fmt.Errorf("resolve scan root: %w", err)
	}
	info, err := os.Stat(absoluteRoot)
	if err != nil {
		return model.Summary{}, fmt.Errorf("open scan root: %w", err)
	}
	if !info.IsDir() {
		return model.Summary{}, fmt.Errorf("scan root is not a directory: %s", absoluteRoot)
	}

	ignored := defaultIgnores()
	for _, item := range options.Ignores {
		item = filepath.ToSlash(strings.Trim(strings.TrimSpace(item), "/"))
		if item != "" {
			ignored[item] = true
		}
	}

	summary := model.Summary{
		Root:      absoluteRoot,
		Findings:  []model.Finding{},
		Counts:    map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
		Threshold: options.Threshold.String(),
	}

	err = filepath.WalkDir(absoluteRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			summary.ScanErrors = append(summary.ScanErrors, walkErr.Error())
			return nil
		}
		rel, err := filepath.Rel(absoluteRoot, path)
		if err != nil {
			summary.ScanErrors = append(summary.ScanErrors, err.Error())
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		if entry.IsDir() {
			if rel != "." && isIgnored(relSlash, ignored) {
				return filepath.SkipDir
			}
			return nil
		}
		if isIgnored(relSlash, ignored) {
			return nil
		}

		fileInfo, err := entry.Info()
		if err != nil {
			summary.ScanErrors = append(summary.ScanErrors, err.Error())
			return nil
		}

		if fileInfo.Mode()&os.ModeSymlink != 0 {
			finding := inspectSymlink(absoluteRoot, path, relSlash)
			if finding != nil {
				summary.Findings = append(summary.Findings, *finding)
			}
			return nil
		}

		if fileInfo.Size() > maxFileSize {
			if finding := inspectBinaryPath(relSlash, fileInfo.Mode()); finding != nil {
				summary.Findings = append(summary.Findings, *finding)
			}
			return nil
		}

		data, err := readLimited(path, maxFileSize)
		if err != nil {
			summary.ScanErrors = append(summary.ScanErrors, fmt.Sprintf("%s: %v", relSlash, err))
			return nil
		}
		summary.FilesScanned++
		summary.BytesScanned += int64(len(data))

		if finding := inspectBinaryPath(relSlash, fileInfo.Mode()); finding != nil {
			summary.Findings = append(summary.Findings, *finding)
		}

		if looksBinary(data) {
			return nil
		}
		context := fileContext{Root: absoluteRoot, Path: path, RelPath: relSlash, Data: data, Mode: uint32(fileInfo.Mode())}
		for _, scanRule := range textRules {
			summary.Findings = append(summary.Findings, scanRule(context)...)
		}
		return nil
	})
	if err != nil {
		return model.Summary{}, fmt.Errorf("walk scan root: %w", err)
	}

	sort.SliceStable(summary.Findings, func(i, j int) bool {
		if summary.Findings[i].Severity != summary.Findings[j].Severity {
			return summary.Findings[i].Severity > summary.Findings[j].Severity
		}
		if summary.Findings[i].Path != summary.Findings[j].Path {
			return summary.Findings[i].Path < summary.Findings[j].Path
		}
		return summary.Findings[i].Rule < summary.Findings[j].Rule
	})

	for _, finding := range summary.Findings {
		summary.Counts[finding.Severity.String()]++
		summary.RiskScore += finding.Severity.Weight()
		if finding.Severity >= options.Threshold {
			summary.ThresholdMet = true
		}
	}
	if summary.RiskScore > 100 {
		summary.RiskScore = 100
	}
	summary.RiskLevel = riskLevel(summary.RiskScore)
	return summary, nil
}

func defaultIgnores() map[string]bool {
	return map[string]bool{
		".git": true, ".hg": true, ".svn": true,
		"node_modules": true, "vendor": true, "dist": true, "build": true,
		".next": true, ".turbo": true, "coverage": true,
	}
}

func isIgnored(path string, ignored map[string]bool) bool {
	path = filepath.ToSlash(path)
	for item := range ignored {
		if path == item || strings.HasPrefix(path, item+"/") {
			return true
		}
	}
	return false
}

func readLimited(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, max+1))
}

func looksBinary(data []byte) bool {
	limit := len(data)
	if limit > 8000 {
		limit = 8000
	}
	for _, b := range data[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

func inspectBinaryPath(rel string, mode fs.FileMode) *model.Finding {
	ext := strings.ToLower(filepath.Ext(rel))
	binaryExtensions := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true, ".msi": true,
		".com": true, ".scr": true, ".bat": true, ".cmd": true, ".ps1": true,
	}
	if binaryExtensions[ext] {
		severity := model.SeverityMedium
		if ext == ".exe" || ext == ".msi" || ext == ".scr" || ext == ".ps1" {
			severity = model.SeverityHigh
		}
		finding := model.NewFinding(
			"BR009", severity, rel, 0,
			"repository contains an executable or dynamic binary artifact", ext,
			"Verify the artifact provenance and checksum, or build it from reviewed source.",
		)
		return &finding
	}
	if mode&0111 != 0 && isScriptExtension(ext) {
		finding := model.NewFinding(
			"BR010", model.SeverityLow, rel, 0,
			"script is marked executable", mode.String(),
			"Review the script before running it; executable status alone is not proof of malicious behavior.",
		)
		return &finding
	}
	return nil
}

func isScriptExtension(ext string) bool {
	switch ext {
	case ".sh", ".bash", ".zsh", ".fish", ".py", ".rb", ".pl":
		return true
	default:
		return false
	}
}

func inspectSymlink(root, path, rel string) *model.Finding {
	target, err := os.Readlink(path)
	if err != nil {
		return nil
	}
	resolved := target
	if !filepath.IsAbs(target) {
		resolved = filepath.Join(filepath.Dir(path), target)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil
	}
	rootWithSeparator := root + string(os.PathSeparator)
	if resolved != root && !strings.HasPrefix(resolved, rootWithSeparator) {
		finding := model.NewFinding(
			"BR011", model.SeverityHigh, rel, 0,
			"symbolic link escapes the repository root", target,
			"Remove the link or verify that its external target is intentional and safe.",
		)
		return &finding
	}
	return nil
}

func riskLevel(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 15:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "clean"
	}
}

func ReadIgnoreFile(root string) ([]string, error) {
	path := filepath.Join(root, ".beforerunignore")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var values []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	return values, scanner.Err()
}
