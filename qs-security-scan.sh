#!/usr/bin/env bash
# Writes ~/.cache/qs-security-status.json, read by SecurityWidget.qml's
# statusFile FileView. Referenced by the README's systemd timer but not
# previously shipped in the repo.
#
# AUR-Malware is skipped entirely unless something executable already sits
# at QS_SEC_AUR_MALWARE -- omitting the key is safe, the widget only shows
# a section when its own presence probe finds the tool installed. Default
# path matches SecurityWidget.qml's own install button, which clones
# nightdevil00/AUR-Malware -- the upstream Atomic-Arch/AUR-Malware this repo
# originally pointed at is gone (404); nightdevil00's fork ships the same
# check-atomic-arch_new.sh entry point.
set -uo pipefail

STATUS_FILE="${QS_SEC_STATUS_FILE:-$HOME/.cache/qs-security-status.json}"
AUR_MALWARE_PATH="${QS_SEC_AUR_MALWARE:-$HOME/.local/share/AUR-Malware/check-atomic-arch_new.sh}"
BUMBLEBEE_BIN="${QS_SEC_BUMBLEBEE:-$HOME/.local/bin/bumblebee}"
CATALOG="${QS_SEC_BUMBLEBEE_CATALOG:-$HOME/.local/share/qs-security/threat-intel}"

aur_json="null"
if [[ -x $AUR_MALWARE_PATH ]]; then
  # --json still prints its live colored progress to stdout before the final
  # JSON blob, and the script's exit code is always 0 regardless of findings
  # -- a plain "last line" / exit-code check always reports "clean" with a
  # disclaimer fragment as the summary, silently hiding real findings. The
  # JSON itself is the last '{'-only line to EOF.
  aur_out=$("$AUR_MALWARE_PATH" --json 2>/dev/null)
  aur_json=$(awk '/^\{$/{f=1} f' <<<"$aur_out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("null"); sys.exit()
verdict = d.get("verdict", "")
status = {"CLEAN": "clean", "WARNINGS": "warn", "COMPROMISED": "fail"}.get(verdict, "error")
s = d.get("summary", {})
fail, warn, total = s.get("fail", 0), s.get("warn", 0), s.get("total", 0)
summary = str(fail) + " failures, " + str(warn) + " warnings out of " + str(total) + " checks"
print(json.dumps({"status": status, "summary": summary}))
')
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
