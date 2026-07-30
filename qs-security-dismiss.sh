#!/usr/bin/env bash
# Marks an AUR-Malware finding as reviewed/dismissed, or reactivates it.
# Called from SecurityWidget.qml (detail tab).
#
# The fingerprint is check-name + a hash of the EXACT detail text -- if the
# detail changes (e.g. a new infected package shows up next to the one
# already reviewed, or a modification date changes), it stops matching what
# was saved and the finding counts as active again on its own. There is no
# way for "dismiss this" to silence a different/new finding.
#
# Only applies to checks that qs-security-scan.sh marks as dismissible
# (heuristics prone to false positives: /etc/hosts, modified shell configs,
# etc.) -- checks that are direct evidence of an actual compromise
# (known-infected package, malicious npm/bun indicator, eBPF, hidden
# processes...) have no dismiss button in the UI, so they should never reach
# here for those, but the filter is also applied on the qs-security-scan.sh
# side just in case.
set -euo pipefail

ACTION="$1"   # dismiss | reactivate
NAME="$2"
DETAIL="$3"
DISMISSED_FILE="${QS_SEC_DISMISSED_FILE:-$HOME/.config/qs-security/dismissed.json}"
STATUS_FILE="${QS_SEC_STATUS_FILE:-$HOME/.cache/qs-security-status.json}"

mkdir -p "$(dirname "$DISMISSED_FILE")"
python3 -c '
import json, sys, hashlib, datetime, os

action, name, detail, dismissed_path, status_path = sys.argv[1:6]
fp = name + "::" + hashlib.sha1(detail.encode()).hexdigest()[:10]

try:
    dismissed = json.load(open(dismissed_path))
except Exception:
    dismissed = {}

if action == "dismiss":
    dismissed[fp] = {"name": name, "dismissedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
else:
    dismissed.pop(fp, None)

os.makedirs(os.path.dirname(dismissed_path), exist_ok=True)
json.dump(dismissed, open(dismissed_path, "w"), indent=2)

# Recompute the AUR-Malware status/summary on the existing status file
# WITHOUT rerunning the scanner (~13s for the network fetch + all 18
# checks) -- dismiss/reactivate is just bookkeeping over an already-run
# scan, it does not need a fresh one to be reflected in the badge.
try:
    status = json.load(open(status_path))
except Exception:
    sys.exit()  # nothing to recompute yet (no scan has run)

aur = status.get("aur_malware")
if not aur or "issues" not in aur:
    sys.exit()

total = None
m = __import__("re").search(r"out of (\d+) checks", aur.get("summary", ""))
if m: total = int(m.group(1))

for issue in aur["issues"]:
    issue_fp = issue.get("fingerprint", "")
    issue["dismissed"] = issue_fp in dismissed

active_fail = sum(1 for i in aur["issues"] if i["status"] == "FAIL" and not i["dismissed"])
active_warn = sum(1 for i in aur["issues"] if i["status"] == "WARN" and not i["dismissed"])
dismissed_n = sum(1 for i in aur["issues"] if i["dismissed"])
aur["status"] = "fail" if active_fail else ("warn" if active_warn else "clean")
if active_fail or active_warn:
    bits = []
    if active_fail: bits.append(str(active_fail) + " failures")
    if active_warn: bits.append(str(active_warn) + " warnings")
    summary = ", ".join(bits) + (" out of " + str(total) + " checks" if total is not None else "")
else:
    summary = (str(total) + "/" + str(total) + " checks passed") if total is not None else "no active findings"
if dismissed_n:
    summary += " (" + str(dismissed_n) + " dismissed)"
aur["summary"] = summary

json.dump(status, open(status_path, "w"))
' "$ACTION" "$NAME" "$DETAIL" "$DISMISSED_FILE" "$STATUS_FILE"
