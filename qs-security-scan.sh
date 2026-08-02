#!/usr/bin/env bash
# Writes ~/.cache/qs-security-status.json for the "Security Scan" Omarchy
# bar-widget plugin (io.github.elynch303.security-scan). The plugin's own
# README documents this script and a systemd timer to run it every 6h, but
# doesn't actually ship either -- reported upstream:
# https://github.com/elynch303/security-scan/issues/1
#
# Extras added in this change on top of #2/#3:
# - Skips the run while a game is active (GameMode), logging that to
#   $LAST_RUN_FILE so the widget can show it instead of silently going stale.
# - A bash-only "persistence" scanner (autostart .desktop entries, user
#   systemd units, crontab) -- same injection-pattern heuristic AUR-Malware
#   already uses for shell configs, applied to the other classic persistence
#   spots malware drops into.
# - Appends a compact entry to $HISTORY_FILE (capped) so past scans aren't
#   thrown away the moment the next one overwrites $STATUS_FILE.
# - Sends a real desktop notification for genuinely NEW active findings
#   (tracked in $NOTIFIED_FILE by fingerprint) instead of only changing the
#   badge color, which nobody sees unless they're already looking at the bar.
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
LAST_RUN_FILE="${QS_SEC_LAST_RUN_FILE:-$HOME/.cache/qs-security-last-run.json}"
HISTORY_FILE="${QS_SEC_HISTORY_FILE:-$HOME/.local/share/qs-security/history.json}"
NOTIFIED_FILE="${QS_SEC_NOTIFIED_FILE:-$HOME/.config/qs-security/notified.json}"
DISMISSED_FILE="${QS_SEC_DISMISSED_FILE:-$HOME/.config/qs-security/dismissed.json}"
HISTORY_CAP=30

# ── skip while gaming ────────────────────────────────────────────────────
# Doing this as the first thing in the script (rather than only via
# ExecCondition= in the systemd unit) means we can actually log *why* the
# run was skipped for the widget to show -- ExecCondition failing stops
# systemd from ever starting this script at all, so it has no chance to
# write anything.
if command -v gamemoded >/dev/null 2>&1 && gamemoded -s 2>/dev/null | grep -q "is active"; then
  mkdir -p "$(dirname "$LAST_RUN_FILE")"
  python3 -c '
import json, sys, datetime
print(json.dumps({
    "skipped": True,
    "reason": "gamemode-active",
    "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}))
' >"$LAST_RUN_FILE"
  exit 0
fi

aur_json="null"
if [[ -x $AUR_MALWARE_PATH ]]; then
  # --json still prints its live colored progress to stdout before the final
  # JSON blob, and the script's exit code is always 0 regardless of findings
  # -- a plain "last line" / exit-code check always reports "clean" with a
  # disclaimer fragment as the summary, silently hiding real findings. The
  # JSON itself is the last '{'-only line to EOF.
  aur_out=$("$AUR_MALWARE_PATH" --json 2>/dev/null)
  aur_json=$(awk '/^\{$/{f=1} f' <<<"$aur_out" | QS_SEC_DISMISSED_FILE="$DISMISSED_FILE" python3 -c '
import json, sys, re, subprocess, hashlib, os

# Checks that are direct evidence of an actual compromise (matched against a
# known-infected package/indicator list, or a very specific rootkit
# artifact) -- these can NEVER be dismissed from the UI, unlike the
# heuristic ones (modification date, /etc/hosts, unusual SUID...) that are
# genuinely prone to legitimate false positives. This is what makes
# "dismiss" safe on a malware-detection tool: you can never silence the
# finding that actually matters, only the heuristic noise around it.
NON_DISMISSIBLE = {
    "Known-infected AUR packages",
    "Malicious npm/bun/pnpm/yarn packages",
    "eBPF artifacts",
    "Hidden processes",
    "Pacman log analysis",
    "ld.so.preload injection",
    "Atomic Arch persistence artifacts",
}

DISMISSED_FILE = os.path.expanduser(os.environ.get("QS_SEC_DISMISSED_FILE", "~/.config/qs-security/dismissed.json"))
try:
    DISMISSED = json.load(open(DISMISSED_FILE))
except Exception:
    DISMISSED = {}

def fingerprint(name, detail):
    return name + "::" + hashlib.sha1(detail.encode()).hexdigest()[:10]

def source_for(name, detail):
    """Best-effort: which package/reason explains this finding, so the
    detail tab does not leave the user guessing. Two cases:
    - Actual malware: the checks that really matter (known-infected AUR
      package, malicious npm/bun indicator) already put the package name in
      the text itself -- it just needs extracting per exact format, a
      generic path regex is not enough for this.
    - False positive with an identifiable cause: e.g. Overwolf entries in
      /etc/hosts are a deliberate telemetry block for CurseForge, not
      malware -- /etc/hosts itself already says so in a comment above the
      entry."""
    # "Known-infected AUR packages" / "Pacman log analysis": AUR-Malware
    # already gives the package name(s) as-is, space-separated, after
    # "package(s):" or "pacman log:".
    if name in ("Known-infected AUR packages", "Pacman log analysis"):
        m = re.search(r"(?:package\(s\)|pacman log):\s*(.+)$", detail)
        if m:
            return m.group(1).strip()
    # "Malicious npm/bun/pnpm/yarn packages" / "...global hook scripts":
    # each hit is "package-name(location)", e.g. "atomic-lockfile(npm-cache)".
    if name in ("Malicious npm/bun/pnpm/yarn packages", "npm/bun/pnpm/yarn global hook scripts"):
        pkgs = re.findall(r"(\S+)\([^)]+\)", detail.split(":", 1)[-1])
        if pkgs:
            return ", ".join(dict.fromkeys(pkgs))
    for domain, _ip in re.findall(r"(\S+)->(\S+)", detail):
        try:
            lines = open("/etc/hosts").read().splitlines()
        except Exception:
            lines = []
        for i, hl in enumerate(lines):
            if domain in hl:
                j = i - 1
                while j >= 0 and lines[j].strip() == "":
                    j -= 1
                if j >= 0 and lines[j].strip().startswith("#"):
                    return lines[j].strip().lstrip("#").strip()
    for path in set(re.findall(r"(/(?:home|etc|usr|var|opt)/\S+?)(?=[\s()\x27\"]|$)", detail)):
        try:
            out = subprocess.run(["pacman", "-Qo", path], capture_output=True, text=True, timeout=2)
            m = re.search(r"is owned by (\S+)", out.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
    return ""

try:
    d = json.load(sys.stdin)
except Exception:
    print("null"); sys.exit()
s = d.get("summary", {})
total = s.get("total", 0)

# Only the checks that did not pass -- the widget uses these for the detail
# tab (see SecurityWidget.qml), no need to carry all 18 every time.
issues = []
for c in d.get("checks", []):
    if c.get("status") == "PASS":
        continue
    name, detail = str(c.get("name", "")), str(c.get("detail", ""))
    fp = fingerprint(name, detail)
    issues.append({
        "name": name, "status": c.get("status", ""), "detail": detail,
        "source": source_for(name, detail),
        "dismissible": name not in NON_DISMISSIBLE,
        "dismissed": fp in DISMISSED,
        "fingerprint": fp,
    })

# The verdict/summary that drives the badge color counts only ACTIVE
# (non-dismissed) findings -- otherwise dismissing a known false positive
# would not stop the badge going red every 6h for the same thing, which is
# exactly the problem this mechanism is meant to solve.
active_fail = sum(1 for i in issues if i["status"] == "FAIL" and not i["dismissed"])
active_warn = sum(1 for i in issues if i["status"] == "WARN" and not i["dismissed"])
dismissed_n = sum(1 for i in issues if i["dismissed"])
status = "fail" if active_fail else ("warn" if active_warn else "clean")
if active_fail or active_warn:
    bits = []
    if active_fail: bits.append(str(active_fail) + " failures")
    if active_warn: bits.append(str(active_warn) + " warnings")
    summary = ", ".join(bits) + " out of " + str(total) + " checks"
else:
    summary = str(total) + "/" + str(total) + " checks passed"
if dismissed_n:
    summary += " (" + str(dismissed_n) + " dismissed)"
print(json.dumps({"status": status, "summary": summary, "issues": issues}))
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

# ── persistence: autostart entries / user systemd units / crontab ────────
# Same injection-pattern heuristic AUR-Malware already uses for shell
# configs (curl|..., bash <(curl...), eval "$(curl|wget|base64|bash|sh ...",
# base64 -d | ...), applied to the other classic spots malware plants
# persistence into: app launchers, user timers/services, cron.
persistence_json=$(QS_SEC_DISMISSED_FILE="$DISMISSED_FILE" python3 -c '
import json, os, re, glob, hashlib, subprocess, datetime

DISMISSED_FILE = os.path.expanduser(os.environ.get("QS_SEC_DISMISSED_FILE", "~/.config/qs-security/dismissed.json"))
try:
    DISMISSED = json.load(open(DISMISSED_FILE))
except Exception:
    DISMISSED = {}

home = os.path.expanduser("~")

INJECTION = re.compile(
    r"(curl[ \t]+[^|]+[ \t]*\||bash[ \t]*<\(curl|eval[ \t]+\"?\$\([ \t]*(curl|wget|base64|bash|sh)([ \t]|[;|)]|$)|base64[ \t]+-d[ \t]*\|)"
)

def fingerprint(name, detail):
    return name + "::" + hashlib.sha1(detail.encode()).hexdigest()[:10]

findings = []  # (check_name, source_path, matched_line)

def scan_lines(path, key_filter=None):
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return
    for line in lines:
        line = line.rstrip("\n")
        if key_filter and not key_filter(line):
            continue
        if INJECTION.search(line):
            yield line.strip()

# .desktop launchers: user-installed apps + autostart entries. Only the
# Exec= line matters -- everything else in a .desktop is display metadata.
for pattern in (home + "/.local/share/applications/*.desktop", home + "/.config/autostart/*.desktop"):
    for path in glob.glob(pattern):
        for line in scan_lines(path, lambda l: l.startswith("Exec=")):
            findings.append(("App launcher persistence", path, line))

# Real user-authored systemd units directly under ~/.config/systemd/user --
# not the *.wants/ enablement symlinks, those point into /usr/lib and are
# package-managed, not something malware would edit.
unit_dir = home + "/.config/systemd/user"
if os.path.isdir(unit_dir):
    for entry in os.listdir(unit_dir):
        path = os.path.join(unit_dir, entry)
        if not (entry.endswith(".service") or entry.endswith(".timer")):
            continue
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        for line in scan_lines(path, lambda l: l.strip().startswith(("ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition"))):
            findings.append(("systemd unit persistence", path, line))

# User crontab, if any.
try:
    out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=3)
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if INJECTION.search(line):
            findings.append(("crontab persistence", "crontab -l", line))
except Exception:
    pass

issues = []
for name, source, line in findings:
    detail = f"{source}: {line}"
    fp = fingerprint(name, detail)
    issues.append({
        "name": name, "status": "FAIL", "detail": detail,
        "source": source,
        "dismissible": True,
        "dismissed": fp in DISMISSED,
        "fingerprint": fp,
    })

active = [i for i in issues if not i["dismissed"]]
dismissed_n = len(issues) - len(active)
status = "fail" if active else "clean"
if active:
    summary = f"{len(active)} persistence finding" + ("s" if len(active) != 1 else "")
else:
    summary = "no persistence indicators"
if dismissed_n:
    summary += f" ({dismissed_n} dismissed)"
print(json.dumps({"status": status, "summary": summary, "issues": issues}))
')

mkdir -p "$(dirname "$STATUS_FILE")"
python3 -c '
import json, sys, datetime
aur, bb, persistence = json.loads(sys.argv[1]), json.loads(sys.argv[2]), json.loads(sys.argv[3])
out = {"checked": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
if aur is not None: out["aur_malware"] = aur
if bb is not None: out["bumblebee"] = bb
out["persistence"] = persistence
print(json.dumps(out))
' "$aur_json" "$bb_json" "$persistence_json" >"$STATUS_FILE"

mkdir -p "$(dirname "$LAST_RUN_FILE")"
python3 -c '
import json, datetime
print(json.dumps({"skipped": False, "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}))
' >"$LAST_RUN_FILE"

# ── history: keep a compact record of each real scan (not the ones skipped
# for gaming, those already exit early above) ────────────────────────────
mkdir -p "$(dirname "$HISTORY_FILE")"
python3 -c '
import json, os, sys

status_path, history_path, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
status = json.load(open(status_path))

entry = {"checked": status.get("checked")}
for key in ("aur_malware", "bumblebee", "persistence"):
    v = status.get(key)
    if v:
        entry[key] = {"status": v.get("status"), "summary": v.get("summary")}

try:
    history = json.load(open(history_path))
    if not isinstance(history, list):
        history = []
except Exception:
    history = []

history.append(entry)
history = history[-cap:]
json.dump(history, open(history_path, "w"))
' "$STATUS_FILE" "$HISTORY_FILE" "$HISTORY_CAP"

# ── real desktop notification, only for ACTIVE and NEW findings (never seen
# before, not already dismissed) -- the badge changing color is invisible to
# anyone who isn't already looking at the bar right then ─────────────────
mkdir -p "$(dirname "$NOTIFIED_FILE")"
notify_summary=$(python3 -c '
import json, os, sys

status_path, notified_path, history_path = sys.argv[1], sys.argv[2], sys.argv[3]
status = json.load(open(status_path))

try:
    notified = json.load(open(notified_path))
    if not isinstance(notified, dict):
        notified = {}
except Exception:
    notified = {}

new_items = []  # (severity, label)
worst = "warn"

for key in ("aur_malware", "persistence"):
    block = status.get(key)
    if not block:
        continue
    for issue in block.get("issues", []):
        if issue.get("dismissed"):
            continue
        fp = issue.get("fingerprint", "")
        if not fp or fp in notified:
            continue
        notified[fp] = True
        label = issue.get("source") or issue.get("name")
        new_items.append((issue.get("status", "WARN"), label))
        if issue.get("status") == "FAIL":
            worst = "fail"

# bumblebee has no per-finding fingerprint -- only notify on the clean ->
# findings transition, by comparing against the previous history entry.
bb = status.get("bumblebee")
if bb and bb.get("status") == "findings":
    try:
        history = json.load(open(history_path))
        prev = history[-2] if len(history) >= 2 else None
    except Exception:
        prev = None
    prev_bb_status = (prev or {}).get("bumblebee", {}).get("status")
    if prev_bb_status != "findings":
        new_items.append(("WARN", "bumblebee: " + bb.get("summary", "")))

json.dump(notified, open(notified_path, "w"))

if new_items:
    print(worst)
    for sev, label in new_items:
        print(sev + "\t" + label)
' "$STATUS_FILE" "$NOTIFIED_FILE" "$HISTORY_FILE")

if [[ -n $notify_summary ]]; then
  worst_severity=$(head -1 <<<"$notify_summary")
  items=$(tail -n +2 <<<"$notify_summary")
  count=$(wc -l <<<"$items")
  urgency=$([[ $worst_severity == fail ]] && echo critical || echo normal)
  # Standard freedesktop icon names so this picks up the user's own icon
  # theme automatically instead of shipping/generating custom artwork.
  icon=$([[ $worst_severity == fail ]] && echo dialog-error || echo dialog-warning)
  body=$(cut -f2 <<<"$items" | head -5 | sed 's/^/• /')
  if [[ $count -gt 5 ]]; then
    body="$body"$'\n'"… and $((count - 5)) more"
  fi
  notify-send --app-name="Security Scan" --urgency="$urgency" --icon="$icon" \
    "$count new security finding$([[ $count != 1 ]] && echo s)" \
    "$body" 2>/dev/null || true
fi
