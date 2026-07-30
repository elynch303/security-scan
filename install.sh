#!/usr/bin/env bash
# Optional install step for the Security Scan plugin.
# - Copies qs-bun-check-oneshot.sh to ~/.local/bin/ so the widget can
#   show the per-project bun-check scan button.
# - Copies qs-security-scan.sh to ~/.local/bin/ and enables the systemd
#   user timer that runs it every 6h -- without this, the widget has
#   nothing writing ~/.cache/qs-security-status.json and never shows a
#   result even once a scanner is installed.
#
# Usage:
#   bash install.sh                     # asks about both steps
#   bash install.sh --bun-check         # install bun-check without prompting
#   bash install.sh --no-bun-check      # skip bun-check
#   bash install.sh --scan-timer        # install+enable the scan timer without prompting
#   bash install.sh --no-scan-timer     # skip the scan timer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

BUN_CHECK_SRC="$SCRIPT_DIR/qs-bun-check-oneshot.sh"
BUN_CHECK_DST="$BIN_DIR/qs-bun-check-oneshot.sh"

SCAN_SCRIPT_SRC="$SCRIPT_DIR/qs-security-scan.sh"
SCAN_SCRIPT_DST="$BIN_DIR/qs-security-scan.sh"
DISMISS_SCRIPT_SRC="$SCRIPT_DIR/qs-security-dismiss.sh"
DISMISS_SCRIPT_DST="$BIN_DIR/qs-security-dismiss.sh"
SCAN_SERVICE_SRC="$SCRIPT_DIR/systemd/qs-security-scan.service"
SCAN_TIMER_SRC="$SCRIPT_DIR/systemd/qs-security-scan.timer"

install_bun_check=
install_scan_timer=

for arg in "$@"; do
  case "$arg" in
    --bun-check) install_bun_check=true ;;
    --no-bun-check) install_bun_check=false ;;
    --scan-timer) install_scan_timer=true ;;
    --no-scan-timer) install_scan_timer=false ;;
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

if [[ -z "$install_scan_timer" ]]; then
  read -rp "Install and enable the periodic security-scan timer (every 6h)? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] && install_scan_timer=true || install_scan_timer=false
fi

if [[ "$install_scan_timer" == true ]]; then
  mkdir -p "$BIN_DIR" "$SYSTEMD_DIR"
  cp "$SCAN_SCRIPT_SRC" "$SCAN_SCRIPT_DST"
  chmod +x "$SCAN_SCRIPT_DST"
  cp "$DISMISS_SCRIPT_SRC" "$DISMISS_SCRIPT_DST"
  chmod +x "$DISMISS_SCRIPT_DST"
  cp "$SCAN_SERVICE_SRC" "$SYSTEMD_DIR/qs-security-scan.service"
  cp "$SCAN_TIMER_SRC" "$SYSTEMD_DIR/qs-security-scan.timer"
  systemctl --user daemon-reload
  systemctl --user enable --now qs-security-scan.timer
  echo "Installed $SCAN_SCRIPT_DST and enabled qs-security-scan.timer"
else
  echo "Skipped scan timer install. Run with --scan-timer later to add it."
fi
