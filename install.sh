#!/usr/bin/env bash
# Optional install step for the Security Scan plugin.
# Copies qs-bun-check-oneshot.sh to ~/.local/bin/ so the widget can
# show the per-project bun-check scan button.
#
# Usage:
#   bash install.sh            # asks whether to install bun-check
#   bash install.sh --bun-check   # install bun-check without prompting
#   bash install.sh --no-bun-check  # skip bun-check
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
BUN_CHECK_SRC="$SCRIPT_DIR/qs-bun-check-oneshot.sh"
BUN_CHECK_DST="$BIN_DIR/qs-bun-check-oneshot.sh"

install_bun_check=

for arg in "$@"; do
  case "$arg" in
    --bun-check) install_bun_check=true ;;
    --no-bun-check) install_bun_check=false ;;
  esac
done

if [[ -z "$install_bun_check" ]]; then
  read -rp "Install bun-check one-shot scan support? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] && install_bun_check=true || install_bun_check=false
fi

if [[ "$install_bun_check" == true ]]; then
  mkdir -p "$BIN_DIR"
  cp "$BUN_CHECK_SRC" "$BUN_CHECK_DST"
  chmod +x "$BUN_CHECK_DST"
  echo "Installed $BUN_CHECK_DST"
else
  echo "Skipped bun-check install. Run with --bun-check later to add it."
fi
