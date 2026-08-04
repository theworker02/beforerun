param(
    [string]$Repository = "beforerun",
    [ValidateSet("public", "private")]
    [string]$Visibility = "public"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is not installed. Install it from https://cli.github.com and run 'gh auth login'."
}

$auth = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "GitHub CLI is not authenticated. Run 'gh auth login' first.`n$auth"
}

if (-not (Test-Path .git)) {
    git init -b main
}

git add .
if (-not (git status --porcelain)) {
    Write-Host "No uncommitted files to publish."
} else {
    git commit -m "Initial release of BeforeRun"
}

$visibilityFlag = if ($Visibility -eq "private") { "--private" } else { "--public" }
$existingRemote = git remote get-url origin 2>$null
if (-not $existingRemote) {
    gh repo create $Repository $visibilityFlag --source . --remote origin --push --description "Scan untrusted repositories before executing project-controlled code."
} else {
    git push -u origin main
}
