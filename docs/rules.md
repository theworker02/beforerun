# Rule reference

BeforeRun rules target repository-controlled behavior that can become active during common developer workflows. Findings are evidence for review, not declarations of malicious intent.

## BR001 — Package lifecycle scripts

Detects lifecycle entries such as `preinstall`, `install`, `postinstall`, and `prepare` in `package.json`. These can run during dependency installation. Severity increases when the command contains downloaders, dynamic interpreters, shell wrappers, or permission changes.

**Review:** inspect the command and every referenced local script before running the package manager.

## BR002 — Workspace automation

Detects VS Code tasks configured with `runOn: folderOpen` and workspace terminal profile overrides. A repository should not silently redefine trusted terminal behavior or execute tasks merely because a folder was opened.

**Review:** open the repository in restricted mode and inspect `.vscode/tasks.json` and `.vscode/settings.json`.

## BR003 — Dev container hooks

Detects initialization, creation, start, and attach hooks in `devcontainer.json`. These hooks are legitimate but execute inside or around a development container during routine setup.

**Review:** inspect hook commands, referenced scripts, mounts, features, and environment variables.

## BR004 — Pipe to shell

Detects download commands such as `curl` or `wget` whose output is piped directly to a shell. This collapses download, inspection, and execution into one step.

**Review:** download separately, verify the expected host and checksum, inspect the file, then run an explicit local copy.

## BR005 — Dynamic PowerShell execution

Detects patterns including `Invoke-Expression`, `IEX`, `DownloadString`, `FromBase64String`, and encoded command flags.

**Review:** decode the complete payload and inspect it in an isolated environment.

## BR006 — Credentials and private keys

Detects sensitive filenames and likely inline assignments for tokens, passwords, secrets, API keys, and private keys. Values are redacted in reports.

**Review:** revoke real credentials, remove them from Git history, and replace them with documented placeholders.

## BR007 — Bidirectional Unicode controls

Detects Unicode controls that can visually reorder source text. These characters sometimes have valid internationalization uses but can also disguise what a compiler interprets.

**Review:** remove the character or document a precise, reviewed reason for it.

## BR008 — Local or relative submodules

Detects `file://` and parent-relative URLs in `.gitmodules`. The effective source may differ between machines and may resolve outside the expected remote trust boundary.

**Review:** use an expected HTTPS or SSH origin and verify repository ownership.

## BR009 — Binary artifacts

Detects executable installers, dynamic libraries, Windows command files, and PowerShell scripts committed to source.

**Review:** prefer reproducible builds from source and verify provenance plus checksums for required artifacts.

## BR010 — Executable scripts

Reports scripts with executable mode. This is low severity because it is common in healthy repositories, but it helps reviewers identify immediate execution surfaces.

**Review:** inspect before running.

## BR011 — Escaping symlinks

Detects symbolic links whose resolved target is outside the scan root.

**Review:** verify the external target is intentional, stable, and safe; otherwise remove the link.
