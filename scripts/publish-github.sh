#!/usr/bin/env sh
set -eu

repository="${1:-beforerun}"
visibility="${2:-public}"

command -v gh >/dev/null 2>&1 || {
  echo "GitHub CLI (gh) is required. Install it and run: gh auth login" >&2
  exit 1
}

gh auth status >/dev/null

if [ ! -d .git ]; then
  git init -b main
fi

git add .
if ! git diff --cached --quiet; then
  git commit -m "Initial release of BeforeRun"
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  if [ "$visibility" = "private" ]; then
    flag="--private"
  else
    flag="--public"
  fi
  gh repo create "$repository" "$flag" --source . --remote origin --push \
    --description "Scan untrusted repositories before executing project-controlled code."
else
  git push -u origin main
fi
