#!/usr/bin/env bash
# Writes ~/.cache/qs-security-status.json, read by SecurityWidget.qml's
# statusFile FileView. Referenced by the README's systemd timer but not
# previously shipped in the repo.
#
# AUR-Malware is skipped entirely unless something executable already sits
# at QS_SEC_AUR_MALWARE -- omitting the key is safe, the widget only shows
# a section when its own presence probe finds the tool installed.
set -uo pipefail

STATUS_FILE="${QS_SEC_STATUS_FILE:-$HOME/.cache/qs-security-status.json}"
AUR_MALWARE_PATH="${QS_SEC_AUR_MALWARE:-/local/applications/AUR-Malware/check-atomic-arch_new.sh}"
BUMBLEBEE_BIN="${QS_SEC_BUMBLEBEE:-$HOME/.local/bin/bumblebee}"
CATALOG="${QS_SEC_BUMBLEBEE_CATALOG:-$HOME/.local/share/qs-security/threat-intel}"

aur_json="null"
if [[ -x $AUR_MALWARE_PATH ]]; then
  aur_out=$("$AUR_MALWARE_PATH" 2>&1)
  aur_code=$?
  aur_status=$([[ $aur_code -eq 0 ]] && echo clean || echo fail)
  aur_json=$(python3 -c '
import json, sys
status, out = sys.argv[1], sys.argv[2].strip()
summary = out.splitlines()[-1] if out else ""
print(json.dumps({"status": status, "summary": summary}))
' "$aur_status" "$aur_out")
fi

bb_json="null"
if [[ -x $BUMBLEBEE_BIN ]]; then
  catalog_args=()
  [[ -d $CATALOG ]] && catalog_args=(--exposure-catalog "$CATALOG")
  scan_out=$("$BUMBLEBEE_BIN" scan --profile baseline "${catalog_args[@]}" 2>/dev/null)
  packages=$(grep -c '"record_type":"package"' <<<"$scan_out")
  findings=$(grep -c '"record_type":"finding"' <<<"$scan_out")
  bb_status=$([[ $findings -gt 0 ]] && echo findings || echo clean)
  bb_json=$(python3 -c '
import json, sys
status, packages, findings = sys.argv[1], sys.argv[2], sys.argv[3]
summary = f"{packages} packages inventoried, {findings} findings against threat-intel catalog"
print(json.dumps({"status": status, "summary": summary}))
' "$bb_status" "$packages" "$findings")
fi

mkdir -p "$(dirname "$STATUS_FILE")"
python3 -c '
import json, sys, datetime
aur, bb = json.loads(sys.argv[1]), json.loads(sys.argv[2])
out = {"checked": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
if aur is not None: out["aur_malware"] = aur
if bb is not None: out["bumblebee"] = bb
print(json.dumps(out))
' "$aur_json" "$bb_json" >"$STATUS_FILE"
