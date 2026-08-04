package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/theworker02/beforerun/internal/model"
)

type fileContext struct {
	Root    string
	Path    string
	RelPath string
	Data    []byte
	Mode    uint32
}

type rule func(fileContext) []model.Finding

var textRules = []rule{
	rulePackageScripts,
	ruleVSCodeAutomation,
	ruleDevcontainerHooks,
	rulePipeToShell,
	rulePowerShellExecution,
	ruleEmbeddedSecrets,
	ruleBidirectionalControls,
	ruleGitmodules,
}

var pipeToShell = regexp.MustCompile(`(?i)(curl|wget)[^\n|]{0,300}\|\s*(sh|bash|zsh|fish|powershell|pwsh)\b`)
var powershellExecution = regexp.MustCompile(`(?i)(invoke-expression|\biex\b|downloadstring\s*\(|frombase64string\s*\(|-(?:enc|encodedcommand)\b)`)
var likelySecret = regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret|password|passwd|private[_-]?key)\s*[:=]\s*["']?[^\s"']{8,}`)

func rulePackageScripts(fc fileContext) []model.Finding {
	if filepath.Base(fc.Path) != "package.json" {
		return nil
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(fc.Data, &pkg); err != nil {
		return nil
	}

	watched := map[string]bool{
		"preinstall":     true,
		"install":        true,
		"postinstall":    true,
		"prepare":        true,
		"prepublish":     true,
		"prepublishonly": true,
	}
	var findings []model.Finding
	for name, command := range pkg.Scripts {
		if !watched[strings.ToLower(name)] {
			continue
		}
		severity := model.SeverityMedium
		if dangerousCommand(command) {
			severity = model.SeverityHigh
		}
		findings = append(findings, model.NewFinding(
			"BR001", severity, fc.RelPath, 0,
			fmt.Sprintf("package lifecycle script %q runs automatically", name),
			trimEvidence(command),
			"Inspect the script and every referenced file before running a package manager install.",
		))
	}
	return findings
}

func ruleVSCodeAutomation(fc fileContext) []model.Finding {
	path := filepath.ToSlash(fc.RelPath)
	if path != ".vscode/tasks.json" && path != ".vscode/settings.json" {
		return nil
	}
	text := strings.ToLower(string(fc.Data))
	var findings []model.Finding
	if strings.Contains(text, `"runon"`) && strings.Contains(text, "folderopen") {
		findings = append(findings, model.NewFinding(
			"BR002", model.SeverityHigh, fc.RelPath, lineOf(fc.Data, []byte("folderOpen")),
			"VS Code task is configured to run when the folder opens", "runOn: folderOpen",
			"Disable automatic task execution and review the command, shell, and dependencies first.",
		))
	}
	if strings.Contains(text, `"terminal.integrated.profiles`) || strings.Contains(text, `"terminal.integrated.defaultprofile`) {
		findings = append(findings, model.NewFinding(
			"BR002", model.SeverityMedium, fc.RelPath, 0,
			"workspace changes integrated terminal profile behavior", "terminal.integrated profile setting",
			"Review workspace terminal settings before trusting the folder.",
		))
	}
	return findings
}

func ruleDevcontainerHooks(fc fileContext) []model.Finding {
	path := filepath.ToSlash(fc.RelPath)
	if !strings.HasSuffix(path, ".devcontainer/devcontainer.json") && filepath.Base(path) != "devcontainer.json" {
		return nil
	}
	keys := []string{"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}
	var findings []model.Finding
	for _, key := range keys {
		if bytes.Contains(bytes.ToLower(fc.Data), bytes.ToLower([]byte(`"`+key+`"`))) {
			findings = append(findings, model.NewFinding(
				"BR003", model.SeverityMedium, fc.RelPath, lineOf(fc.Data, []byte(key)),
				fmt.Sprintf("dev container hook %q can execute commands", key), key,
				"Review the hook and referenced scripts before building or opening the dev container.",
			))
		}
	}
	return findings
}

func rulePipeToShell(fc fileContext) []model.Finding {
	if !isExecutionSurface(fc.RelPath) {
		return nil
	}
	match := pipeToShell.Find(fc.Data)
	if match == nil {
		return nil
	}
	return []model.Finding{model.NewFinding(
		"BR004", model.SeverityCritical, fc.RelPath, lineOf(fc.Data, match),
		"remote content is piped directly into a command shell", trimEvidence(string(match)),
		"Download the content separately, verify its source and checksum, then inspect it before execution.",
	)}
}

func rulePowerShellExecution(fc fileContext) []model.Finding {
	if !isExecutionSurface(fc.RelPath) {
		return nil
	}
	match := powershellExecution.Find(fc.Data)
	if match == nil {
		return nil
	}
	severity := model.SeverityHigh
	text := strings.ToLower(string(fc.Data))
	if strings.Contains(text, "downloadstring") || strings.Contains(text, "encodedcommand") || strings.Contains(text, "-enc ") {
		severity = model.SeverityCritical
	}
	return []model.Finding{model.NewFinding(
		"BR005", severity, fc.RelPath, lineOf(fc.Data, match),
		"PowerShell dynamic or encoded execution pattern detected", trimEvidence(string(match)),
		"Decode and inspect the complete command in an isolated environment before execution.",
	)}
}

func ruleEmbeddedSecrets(fc fileContext) []model.Finding {
	base := strings.ToLower(filepath.Base(fc.Path))
	isSensitiveName := base == ".env" || base == ".npmrc" || base == ".pypirc" || base == "credentials" || base == "id_rsa" || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key")
	match := likelySecret.Find(fc.Data)
	if match != nil {
		lowerMatch := strings.ToLower(string(match))
		if strings.Contains(lowerMatch, "regexp.") || strings.Contains(lowerMatch, "mustcompile") || strings.Contains(lowerMatch, "<redacted>") {
			match = nil
		}
	}
	if !isSensitiveName && match == nil {
		return nil
	}
	if strings.Contains(base, "example") || strings.Contains(base, "sample") || strings.Contains(base, "template") {
		return nil
	}
	severity := model.SeverityHigh
	if base == "id_rsa" || strings.HasSuffix(base, ".key") {
		severity = model.SeverityCritical
	}
	evidence := "sensitive filename"
	line := 0
	if match != nil {
		evidence = redactSecret(string(match))
		line = lineOf(fc.Data, match)
	}
	return []model.Finding{model.NewFinding(
		"BR006", severity, fc.RelPath, line,
		"possible credential or private key material is committed", evidence,
		"Revoke exposed credentials, remove the file from Git history, and provide a sanitized example file instead.",
	)}
}

func ruleBidirectionalControls(fc fileContext) []model.Finding {
	if !utf8.Valid(fc.Data) {
		return nil
	}
	controls := []rune{'\u202A', '\u202B', '\u202D', '\u202E', '\u202C', '\u2066', '\u2067', '\u2068', '\u2069'}
	text := string(fc.Data)
	for _, r := range controls {
		if strings.ContainsRune(text, r) {
			return []model.Finding{model.NewFinding(
				"BR007", model.SeverityHigh, fc.RelPath, 0,
				"bidirectional Unicode control character can disguise source code", fmt.Sprintf("Unicode %U", r),
				"Remove the control character or document an explicit, reviewed reason for its presence.",
			)}
		}
	}
	return nil
}

func ruleGitmodules(fc fileContext) []model.Finding {
	if filepath.Base(fc.Path) != ".gitmodules" {
		return nil
	}
	text := strings.ToLower(string(fc.Data))
	if strings.Contains(text, "file://") || strings.Contains(text, "url = ../") || strings.Contains(text, "url = ..\\") {
		return []model.Finding{model.NewFinding(
			"BR008", model.SeverityHigh, fc.RelPath, 0,
			"submodule uses a local or relative URL", "file or relative submodule URL",
			"Replace it with an expected HTTPS or SSH origin and verify the target repository.",
		)}
	}
	return nil
}

func isExecutionSurface(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "makefile" || base == "dockerfile" || base == "justfile" || base == "taskfile.yml" || base == "taskfile.yaml" || base == "package.json" {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".pl", ".yml", ".yaml":
		return true
	default:
		return false
	}
}

func dangerousCommand(command string) bool {
	lower := strings.ToLower(command)
	patterns := []string{"curl ", "wget ", "powershell", "pwsh", "invoke-expression", "node -e", "python -c", "bash -c", "sh -c", "chmod +x", "certutil", "bitsadmin"}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func lineOf(data, match []byte) int {
	index := bytes.Index(bytes.ToLower(data), bytes.ToLower(match))
	if index < 0 {
		return 0
	}
	return bytes.Count(data[:index], []byte("\n")) + 1
}

func trimEvidence(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if len(value) > 180 {
		return value[:177] + "..."
	}
	return value
}

func redactSecret(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '=' || r == ':' })
	if len(parts) == 0 {
		return "possible secret"
	}
	return strings.TrimSpace(parts[0]) + "=<redacted>"
}
