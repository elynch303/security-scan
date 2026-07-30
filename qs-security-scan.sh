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

mkdir -p "$(dirname "$STATUS_FILE")"
python3 -c '
import json, sys, datetime
aur, bb = json.loads(sys.argv[1]), json.loads(sys.argv[2])
out = {"checked": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
if aur is not None: out["aur_malware"] = aur
if bb is not None: out["bumblebee"] = bb
print(json.dumps(out))
' "$aur_json" "$bb_json" >"$STATUS_FILE"
