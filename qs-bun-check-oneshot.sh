#!/usr/bin/env bash
# One-shot bun-checkV2 run against a user-picked project folder. Not part of
# the periodic security scan (qs-security-scan.sh) — bun-checkV2 is a
# per-project dev-env check, not a system-wide scan.
set -uo pipefail

BUN_CHECK="${QS_BUN_CHECK:-/local/applications/bun-checkV2.sh}"

dir="$(zenity --file-selection --directory --title="bun-check: pick a project folder" 2>/dev/null)"
[ -z "$dir" ] && exit 0   # cancelled

omarchy-launch-floating-terminal-with-presentation "$BUN_CHECK $(printf '%q' "$dir")"
