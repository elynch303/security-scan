import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Security-status badge for Omarchy bars.
//
// Main view  — live scan results from ~/.cache/qs-security-status.json
//            — per-scanner sections hidden when not installed or toggled off
//            — gear icon opens Settings view, history icon opens History
//
// Settings view — install / uninstall each scanner with one click
//               — toggle each scanner on/off (widget-side preference)
//               — preferences persisted to ~/.config/qs-security/settings.json
//
// Scanners:
//   AUR-Malware  git clone to ~/.local/share/AUR-Malware (or QS_SEC_AUR_MALWARE)
//   bumblebee    go install github.com/anchore/bumblebee@latest
//   bun-check    bundled script → ~/.local/bin/qs-bun-check-oneshot.sh
//   persistence  bash-only, always available — no install step. Scans
//                autostart .desktop entries, user systemd units and
//                crontab for the same injection pattern AUR-Malware already
//                checks shell configs for.
Panel {
  id: root
  moduleName: "local.security-scan"

  // Same pattern as the Dropbox/Tailscale panels shipped with Omarchy:
  // inherit the active bar's colors instead of a fixed theme token, so the
  // widget follows whichever theme/bar is currently active.
  readonly property color foreground: bar ? bar.foreground : "#cacccc"
  readonly property color urgent: bar ? bar.urgent : "#a55555"

  // ── scan state ──────────────────────────────────────────────────────────
  property var securityStatus: ({})
  property bool securityScanning: false

  readonly property var aur: securityStatus.aur_malware || ({})
  readonly property var bb:  securityStatus.bumblebee   || ({})
  readonly property var persistence: securityStatus.persistence || ({})
  readonly property bool everScanned: !!securityStatus.checked

  // ── last-run / next-run state (gaming-aware timer) ─────────────────────
  property var lastRun: ({})
  readonly property bool lastRunSkipped: lastRun.skipped === true
  // Matches OnUnitActiveSec= in qs-security-scan.timer -- kept as a plain
  // property (not read from the unit file) so this stays simple; if that
  // interval ever changes, update both.
  readonly property int scanIntervalHours: 6
  readonly property string nextScanText: {
    var at = lastRun.at
    if (!at) return ""
    var t = new Date(at).getTime()
    if (isNaN(t)) return ""
    var nextT = t + root.scanIntervalHours * 3600000
    var mins = Math.round((nextT - Date.now()) / 60000)
    var etaText = mins <= 0 ? "shortly" : (mins < 60 ? "in " + mins + "m" : "in " + Math.round(mins / 60) + "h")
    return root.lastRunSkipped
      ? "skipped " + root.relTime(at) + " (game active) · next " + etaText
      : "next " + etaText
  }

  // ── history ──────────────────────────────────────────────────────────
  property var scanHistory: []
  // Most recent first -- the file is appended to in chronological order.
  readonly property var scanHistoryRecent: {
    var out = scanHistory.slice()
    out.reverse()
    return out
  }
  function historyEntryStatus(entry) {
    var sev = { fail: 2, error: 2, warn: 1, findings: 1 }
    var worst = 0
    ;["aur_malware", "bumblebee", "persistence"].forEach(function(k) {
      if (entry[k]) worst = Math.max(worst, sev[entry[k].status] || 0)
    })
    return worst === 2 ? "fail" : (worst === 1 ? "warn" : "clean")
  }
  function historyEntrySummary(entry) {
    var parts = []
    ;["aur_malware", "bumblebee", "persistence"].forEach(function(k) {
      if (entry[k] && entry[k].summary) parts.push(entry[k].summary)
    })
    return parts.join(" · ")
  }

  // ── user preferences (persisted) ───────────────────────────────────────
  property var userSettings: ({})
  readonly property bool aurUserEnabled: userSettings.aur_enabled !== false
  readonly property bool bbUserEnabled:  userSettings.bb_enabled  !== false
  readonly property bool bunUserEnabled: userSettings.bun_enabled !== false

  // ── installation state (from probes, independent of scan history) ──────
  property bool aurInstalled: false
  property bool bbInstalled:  false
  property bool bunInstalled: false

  // ── effective availability for the main view ────────────────────────────
  readonly property bool aurAvailable: aurInstalled && aurUserEnabled
  readonly property bool bbAvailable:  bbInstalled  && bbUserEnabled
  readonly property bool bunCheckEnabled: bunInstalled && bunUserEnabled
  // Persistence is pure bash, nothing to install -- always active.
  readonly property bool persistenceAvailable: true
  readonly property bool anyScanner:      aurAvailable || bbAvailable || root.persistenceAvailable

  // ── settings panel UI state ─────────────────────────────────────────────
  property bool showSettings: false
  property bool showAurDetail: false
  property bool showPersistenceDetail: false
  property bool showHistory: false

  function closeSubviews() {
    root.showSettings = false
    root.showAurDetail = false
    root.showPersistenceDetail = false
    root.showHistory = false
  }

  // Grouped by source (package/reason identified by qs-security-scan.sh,
  // e.g. a comment in /etc/hosts, the package that owns a file, or the
  // launcher/unit/crontab path for persistence) -- without this, every
  // finding was a loose block of text with no indication of WHAT it
  // belongs to.
  function groupIssues(issues) {
    var map = {}, order = []
    for (var i = 0; i < issues.length; i++) {
      var it = issues[i]
      var key = (it.source && it.source !== "") ? it.source : "OTHER"
      if (!map[key]) { map[key] = []; order.push(key) }
      map[key].push(it)
    }
    // "OTHER" (no identified source) always last -- specific things (a
    // named package/app) first, generic afterward.
    order.sort(function(a, b) {
      if (a === "OTHER") return 1
      if (b === "OTHER") return -1
      return 0
    })
    var out = []
    for (var j = 0; j < order.length; j++) out.push({ source: order[j], issues: map[order[j]] })
    return out
  }

  readonly property var aurIssues: aur.issues || []
  readonly property var aurGroups: root.groupIssues(root.aurIssues)

  readonly property var persistenceIssues: persistence.issues || []
  readonly property var persistenceGroups: root.groupIssues(root.persistenceIssues)

  property bool   aurOpBusy: false
  property string aurOpMsg:  ""
  property bool   aurOpError: false

  property bool   bbOpBusy: false
  property string bbOpMsg:  ""
  property bool   bbOpError: false

  property bool   bunOpBusy: false
  property string bunOpMsg:  ""
  property bool   bunOpError: false

  // ── paths ───────────────────────────────────────────────────────────────
  readonly property string home: Quickshell.env("HOME")

  readonly property string aurEffectivePath: {
    var ov = Quickshell.env("QS_SEC_AUR_MALWARE")
    return ov ? ov : root.home + "/.local/share/AUR-Malware/check-atomic-arch_new.sh"
  }
  readonly property string aurMalwareDir: {
    var p = root.aurEffectivePath
    var i = p.lastIndexOf("/")
    return i > 0 ? p.substring(0, i) : root.home + "/.local/share/AUR-Malware"
  }

  readonly property string bunDst: home + "/.local/bin/qs-bun-check-oneshot.sh"
  readonly property string bunSrc: home + "/.config/omarchy/plugins/io.github.elynch303.security-scan/qs-bun-check-oneshot.sh"
  readonly property string settingsPath: home + "/.config/qs-security/settings.json"
  readonly property string lastRunPath: home + "/.cache/qs-security-last-run.json"
  readonly property string historyPath: home + "/.local/share/qs-security/history.json"

  // ── file watchers ───────────────────────────────────────────────────────
  FileView {
    id: statusFile
    path: home + "/.cache/qs-security-status.json"
    watchChanges: true
    onFileChanged: statusFile.reload()
    onLoaded: {
      try { root.securityStatus = JSON.parse(statusFile.text()) } catch (e) {}
      root.securityScanning = false
    }
    onLoadFailed: {}
  }

  FileView {
    id: lastRunFile
    path: root.lastRunPath
    watchChanges: true
    onFileChanged: lastRunFile.reload()
    onLoaded: {
      try { root.lastRun = JSON.parse(lastRunFile.text()) } catch (e) {}
    }
    onLoadFailed: { root.lastRun = ({}) }
  }

  FileView {
    id: historyFile
    path: root.historyPath
    watchChanges: true
    onFileChanged: historyFile.reload()
    onLoaded: {
      try { root.scanHistory = JSON.parse(historyFile.text()) } catch (e) { root.scanHistory = [] }
    }
    onLoadFailed: { root.scanHistory = [] }
  }

  FileView {
    id: settingsFile
    path: root.settingsPath
    watchChanges: true
    onFileChanged: settingsFile.reload()
    onLoaded: {
      try { root.userSettings = JSON.parse(settingsFile.text()) } catch (e) {}
    }
    onLoadFailed: { root.userSettings = ({}) }
  }

  FileView {
    id: bunProbe
    path: root.bunDst
    onLoaded:     root.bunInstalled = true
    onLoadFailed: root.bunInstalled = false
  }

  FileView {
    id: aurProbe
    path: root.aurEffectivePath
    onLoaded:     root.aurInstalled = true
    onLoadFailed: root.aurInstalled = false
  }

  FileView {
    id: bbProbe
    path: home + "/.local/bin/bumblebee"
    onLoaded:     root.bbInstalled = true
    onLoadFailed: root.bbInstalled = false
  }

  Component.onCompleted: {
    statusFile.reload()
    lastRunFile.reload()
    historyFile.reload()
    settingsFile.reload()
    bunProbe.reload()
    aurProbe.reload()
    bbProbe.reload()
  }

  // re-probe when settings opens so the panel always shows current state
  onShowSettingsChanged: {
    if (showSettings) {
      aurProbe.reload()
      bunProbe.reload()
      bbProbe.reload()
    }
  }

  // ── settings persistence ────────────────────────────────────────────────
  function saveSettings(aurEnabled, bbEnabled, bunEnabled) {
    var json = JSON.stringify({
      aur_enabled: aurEnabled,
      bb_enabled:  bbEnabled,
      bun_enabled: bunEnabled
    })
    settingsSaveProc.command = [
      "bash", "-c",
      "mkdir -p \"$(dirname \"$1\")\" && printf '%s' \"$2\" > \"$1\"",
      "--", root.settingsPath, json
    ]
    settingsSaveProc.running = false
    settingsSaveProc.running = true
  }

  function toggleAur() { root.saveSettings(!root.aurUserEnabled, root.bbUserEnabled,  root.bunUserEnabled) }
  function toggleBB()  { root.saveSettings(root.aurUserEnabled,  !root.bbUserEnabled, root.bunUserEnabled) }
  function toggleBun() { root.saveSettings(root.aurUserEnabled,  root.bbUserEnabled,  !root.bunUserEnabled) }

  Process {
    id: settingsSaveProc
    onExited: settingsFile.reload()
  }

  // ── periodic rescan ─────────────────────────────────────────────────────
  Process {
    id: rescanProc
    command: [home + "/.local/bin/qs-security-scan.sh"]
    running: false
    onExited: { statusFile.reload(); lastRunFile.reload(); historyFile.reload() }
  }

  function rescan() {
    root.securityScanning = true
    rescanProc.running = false
    rescanProc.running = true
  }

  Timer {
    interval: 60000
    running: root.securityScanning
    onTriggered: { root.securityScanning = false; rescanProc.running = false }
  }

  // ── dismiss / reactivate a heuristic finding ────────────────────────────
  // Only for issue.dismissible === true -- qs-security-scan.sh never marks
  // as dismissible the checks that are direct evidence of a compromise
  // (known-infected package, etc.), so this doesn't need checking here too:
  // the row's button doesn't even exist for those.
  Process {
    id: issueDismissProc
    // qs-security-dismiss.sh recomputes the status file directly (no
    // rescan, ~13s), so a reload is all that's needed -- no root.rescan(),
    // which would relaunch the full scan.
    onExited: statusFile.reload()
  }
  function setIssueDismissed(name, detailText, dismissed, blockKey) {
    issueDismissProc.command = [home + "/.local/bin/qs-security-dismiss.sh",
                                 dismissed ? "dismiss" : "reactivate", name, detailText, blockKey]
    issueDismissProc.running = false
    issueDismissProc.running = true
  }

  // ── install / uninstall processes ───────────────────────────────────────
  Process {
    id: aurInstallProc
    onExited: function(code) {
      root.aurOpBusy  = false
      root.aurOpError = (code !== 0)
      root.aurOpMsg   = code === 0 ? "Installed — run a scan to verify" : "Install failed (git may not be in PATH)"
      aurProbe.reload()
    }
  }
  Process {
    id: aurUninstallProc
    onExited: function(code) {
      root.aurOpBusy  = false
      root.aurOpError = (code !== 0)
      root.aurOpMsg   = code === 0 ? "Uninstalled" : "Uninstall failed"
      aurProbe.reload()
    }
  }

  Process {
    id: bbInstallProc
    onExited: function(code) {
      root.bbOpBusy  = false
      root.bbOpError = (code !== 0)
      root.bbOpMsg   = code === 0 ? "Installed — run a scan to verify" : "Install failed — is go installed? (mise, pacman -S go)"
      bbProbe.reload()
    }
  }
  Process {
    id: bbUninstallProc
    onExited: function(code) {
      root.bbOpBusy  = false
      root.bbOpError = (code !== 0)
      root.bbOpMsg   = code === 0 ? "Uninstalled" : "Uninstall failed"
      bbProbe.reload()
    }
  }

  Process {
    id: bunInstallProc
    onExited: function(code) {
      root.bunOpBusy  = false
      root.bunOpError = (code !== 0)
      root.bunOpMsg   = code === 0 ? "Installed" : "Install failed — plugin source not found?"
      bunProbe.reload()
    }
  }
  Process {
    id: bunUninstallProc
    onExited: function(code) {
      root.bunOpBusy  = false
      root.bunOpError = (code !== 0)
      root.bunOpMsg   = code === 0 ? "Uninstalled" : "Uninstall failed"
      bunProbe.reload()
    }
  }

  // ── install / uninstall actions ─────────────────────────────────────────
  function installAur() {
    root.aurOpBusy = true; root.aurOpMsg = ""; root.aurOpError = false
    aurInstallProc.command = [
      "bash", "-c",
      "mkdir -p \"$(dirname \"$0\")\" && git clone https://github.com/nightdevil00/AUR-Malware.git \"$0\"",
      root.aurMalwareDir
    ]
    aurInstallProc.running = false; aurInstallProc.running = true
  }
  function uninstallAur() {
    root.aurOpBusy = true; root.aurOpMsg = ""; root.aurOpError = false
    aurUninstallProc.command = ["bash", "-c", "rm -rf \"$0\"", root.aurMalwareDir]
    aurUninstallProc.running = false; aurUninstallProc.running = true
  }

  function installBB() {
    root.bbOpBusy = true; root.bbOpMsg = "Installing via go…"; root.bbOpError = false
    bbInstallProc.command = [
      "/usr/bin/mise", "exec", "--", "sh", "-c",
      "GOBIN=$HOME/.local/bin go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest"
    ]
    bbInstallProc.running = false; bbInstallProc.running = true
  }
  function uninstallBB() {
    root.bbOpBusy = true; root.bbOpMsg = ""; root.bbOpError = false
    bbUninstallProc.command = ["bash", "-c", "rm -f \"$HOME/.local/bin/bumblebee\""]
    bbUninstallProc.running = false; bbUninstallProc.running = true
  }

  function installBun() {
    root.bunOpBusy = true; root.bunOpMsg = "Downloading…"; root.bunOpError = false
    bunInstallProc.command = [
      "bash", "-c",
      "mkdir -p \"$(dirname \"$1\")\" && curl -fsSL \"$0\" -o \"$1\" && chmod +x \"$1\"",
      "https://raw.githubusercontent.com/elynch303/security-scan/main/qs-bun-check-oneshot.sh",
      root.bunDst
    ]
    bunInstallProc.running = false; bunInstallProc.running = true
  }
  function uninstallBun() {
    root.bunOpBusy = true; root.bunOpMsg = ""; root.bunOpError = false
    bunUninstallProc.command = ["bash", "-c", "rm -f \"$0\"", root.bunDst]
    bunUninstallProc.running = false; bunUninstallProc.running = true
  }

  // ── helpers ─────────────────────────────────────────────────────────────
  readonly property string overallStatus: {
    var sev = { fail: 2, error: 2, warn: 1, findings: 1 }
    var worst = 0
    if (root.aurAvailable) worst = Math.max(worst, sev[root.aur.status] || 0)
    if (root.bbAvailable)  worst = Math.max(worst, sev[root.bb.status]  || 0)
    if (root.persistenceAvailable && root.everScanned) worst = Math.max(worst, sev[root.persistence.status] || 0)
    return worst === 2 ? "fail" : (worst === 1 ? "warn" : "clean")
  }

  function badgeColor() {
    if (!root.anyScanner) return Color.accent
    if (!root.everScanned) return Color.accent
    if (root.overallStatus === "fail") return root.urgent
    if (root.overallStatus === "warn") return "#e8a33d"
    return Color.accent
  }

  function statusColor(s) {
    if (s === "fail" || s === "error") return root.urgent
    if (s === "warn" || s === "findings") return "#e8a33d"
    return Color.accent
  }
  function statusLabel(s) {
    if (s === "clean")    return "CLEAN"
    if (s === "warn")     return "WARNINGS"
    if (s === "fail")     return "COMPROMISED"
    if (s === "findings") return "FINDINGS"
    if (s === "error")    return "ERROR"
    return "—"
  }
  function relTime(iso) {
    if (!iso) return ""
    var t = new Date(iso).getTime()
    if (isNaN(t)) return ""
    var mins = Math.max(0, Math.round((Date.now() - t) / 60000))
    if (mins < 1)  return "just now"
    if (mins < 60) return mins + "m ago"
    var hrs = Math.round(mins / 60)
    if (hrs < 24)  return hrs + "h ago"
    return Math.round(hrs / 24) + "d ago"
  }

  readonly property string tooltipText: {
    if (!root.anyScanner && !root.bunCheckEnabled) return "No scanners active\nClick to install"
    if (root.securityScanning) return "Scanning…"
    if (!root.everScanned) return "Security scan pending\nClick to view details"
    var parts = []
    if (root.aurAvailable && root.aur.status) parts.push("AUR-Malware: " + (root.aur.summary || root.aur.status))
    if (root.bbAvailable  && root.bb.status)  parts.push("bumblebee: "   + (root.bb.summary  || root.bb.status))
    if (root.persistenceAvailable && root.persistence.status) parts.push("persistence: " + (root.persistence.summary || root.persistence.status))
    return parts.join("\n") + "\nClick to view details"
  }

  // ── bar chrome ──────────────────────────────────────────────────────────
  visible: true
  implicitWidth:  button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.securityScanning ? "…" : "󰒙"
    slotSize: Style.bar.statusSlot
    fontSize: Style.bar.iconFont
    tooltipText: root.tooltipText
    activeColor: root.badgeColor()
    active: root.aurInstalled || root.bbInstalled || root.bunInstalled
    onPressed: {
      root.toggle()
      if (!root.opened) root.closeSubviews()
    }
  }

  // ── detached one-shot runners ────────────────────────────────────────────
  Process {
    id: bunCheckRunner
    command: ["setsid", "-f", "bash", home + "/.local/bin/qs-bun-check-oneshot.sh"]
  }
  Process {
    id: bumblebeeRunner
    command: ["setsid", "-f", "bash", home + "/.local/bin/qs-bumblebee-oneshot.sh"]
  }

  // ── popup ────────────────────────────────────────────────────────────────
  // Panel + KeyboardPanel (rather than BarWidget + PopupCard) to match the
  // rest of Omarchy's first-party bar panels (Audio, Network, Bluetooth...),
  // which all get keyboard navigation (Escape closes, Tab switches panels)
  // this way. See qs.Ui's Panel.qml/KeyboardPanel.qml for what each provides.
  KeyboardPanel {
    id: detail
    anchorItem: button
    bar: root.bar
    owner: root
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: detail.fittedContentWidth(Style.space(380))
    contentHeight: detail.fittedContentHeight(
      (root.showSettings ? settingsCol.implicitHeight
        : root.showHistory ? historyCol.implicitHeight
        : root.showPersistenceDetail ? persistenceDetailCol.implicitHeight
        : root.showAurDetail ? aurDetailCol.implicitHeight
        : mainCol.implicitHeight), Style.space(560))

    onOpenChanged: if (!open) root.closeSubviews()

    // ── reusable action button component ──────────────────────────────────
    component ActionBtn: Rectangle {
      id: ab
      property string label: ""
      property bool destructive: false
      property bool busy: false
      signal clicked()

      width: parent.width
      height: Style.spacing.controlHeight
      radius: Style.cornerRadius
      visible: !busy
      color: abMa.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
      border.width: 1
      border.color: destructive
        ? Qt.rgba(root.urgent.r, root.urgent.g, root.urgent.b, abMa.containsMouse ? 0.65 : 0.3)
        : (abMa.containsMouse ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15))
      Behavior on color { ColorAnimation { duration: 120 } }
      Text {
        anchors.centerIn: parent
        text: ab.label
        color: ab.destructive
          ? (abMa.containsMouse ? root.urgent : Qt.rgba(root.urgent.r, root.urgent.g, root.urgent.b, 0.7))
          : (abMa.containsMouse ? Color.accent : root.foreground)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
      MouseArea {
        id: abMa
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: ab.clicked()
      }
    }

    // ── scanner row component (settings view) ─────────────────────────────
    component ScannerRow: Column {
      id: sr
      property string title: ""
      property bool   installed: false
      property bool   userEnabled: true
      property bool   opBusy: false
      property string opMsg: ""
      property bool   opError: false
      signal installClicked()
      signal uninstallClicked()
      signal toggleClicked()

      width: parent.width
      spacing: Style.spacing.sm

      PanelSeparator { foreground: root.foreground }

      Item {
        width: parent.width
        height: srHeader.implicitHeight + Style.spacing.xs * 2

        PanelSectionHeader {
          id: srHeader
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          foreground: root.foreground
          text: sr.title
        }

        ToggleSwitch {
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: sr.installed
          checked: sr.userEnabled
          busy: sr.opBusy
          foreground: root.foreground
          onToggled: sr.toggleClicked()
        }

        Text {
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: !sr.installed
          text: "Not installed"
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.42)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }

      ActionBtn {
        label: sr.installed ? "Uninstall" : "Install"
        destructive: sr.installed
        busy: sr.opBusy
        onClicked: sr.installed ? sr.uninstallClicked() : sr.installClicked()
      }

      Text {
        width: parent.width
        visible: sr.opBusy || sr.opMsg !== ""
        text: sr.opBusy ? "Working…" : sr.opMsg
        color: sr.opError
          ? root.urgent
          : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.58)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.Wrap
      }
    }

    // ── reusable issue-detail row (used for both AUR-Malware and
    // persistence -- same structure, different data source) ───────────────
    component IssueRow: Column {
      required property var modelData
      required property string blockKey
      width: parent.width
      spacing: Style.spacing.xxs
      opacity: modelData.dismissed ? 0.5 : 1.0
      Behavior on opacity { NumberAnimation { duration: 120 } }
      PanelSeparator { foreground: root.foreground }
      Item {
        width: parent.width
        height: Math.max(issueNameText.implicitHeight, issueDismissBtn.implicitHeight)
        Text {
          id: issueNameText
          anchors.left: parent.left
          anchors.right: issueDismissBtn.visible ? issueDismissBtn.left : parent.right
          anchors.rightMargin: issueDismissBtn.visible ? Style.spacing.xs : 0
          text: (modelData.status === "FAIL" ? "✕ " : "⚠ ") + modelData.name
            + (modelData.dismissed ? " (dismissed)" : "")
          color: modelData.status === "FAIL" ? root.urgent : "#e8a33d"
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          font.bold: true
          wrapMode: Text.Wrap
        }
        PanelActionButton {
          id: issueDismissBtn
          anchors.right: parent.right
          anchors.top: parent.top
          visible: modelData.dismissible === true
          iconText: modelData.dismissed ? "󰑙" : "󰄬"
          foreground: root.foreground
          tooltipText: modelData.dismissed ? "Reactivate" : "Dismiss (reviewed false positive)"
          onClicked: root.setIssueDismissed(modelData.name, modelData.detail, !modelData.dismissed, blockKey)
        }
      }
      Text {
        width: parent.width
        text: modelData.detail
        color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.75)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.Wrap
      }
    }

    component IssueDetailView: Column {
      id: idv
      property string headerTitle: ""
      property var groups: []
      property string blockKey: ""
      signal backClicked()

      width: panelFlick.width
      spacing: Style.spacing.md

      Item {
        width: parent.width
        height: Style.spacing.xxl
        PanelActionButton {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰁍"
          foreground: root.foreground
          tooltipText: "Back"
          onClicked: idv.backClicked()
        }
        Text {
          anchors.centerIn: parent
          text: idv.headerTitle
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.7)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }
      }

      Repeater {
        model: idv.groups
        delegate: Column {
          required property var modelData
          width: idv.width
          spacing: Style.spacing.sm
          PanelSectionHeader { foreground: root.foreground; text: modelData.source.toUpperCase() }
          Repeater { model: modelData.issues; delegate: IssueRow { blockKey: idv.blockKey } }
        }
      }
    }

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: (root.showSettings ? settingsCol.implicitHeight
          : root.showHistory ? historyCol.implicitHeight
          : root.showPersistenceDetail ? persistenceDetailCol.implicitHeight
          : root.showAurDetail ? aurDetailCol.implicitHeight
          : mainCol.implicitHeight)
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

    // ═══════════════════════════════════════════════════════════════════════
    // Main view
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: mainCol
      visible: !root.showSettings && !root.showAurDetail && !root.showPersistenceDetail && !root.showHistory
      width: panelFlick.width
      spacing: Style.space(12)

      // Header: hero (icon + title + status) + next-scan line, grouped in
      // their own column with tight spacing -- the big gap (Style.space(12)
      // above) is what separates this block from the rest of the sections,
      // not what separates the hero from its own status line. The icon
      // sits in a fixed-width slot (heroIconSlot) so the "next scan" line
      // below can line up precisely under the hero's title.
      Column {
        id: heroBlock
        width: parent.width
        spacing: Style.space(4)
        readonly property real heroIconSlot: Style.space(28)

        Item {
          width: parent.width
          implicitHeight: hero.implicitHeight

          PanelHero {
            id: hero
            width: parent.width
            title: "Security"
            meta: root.everScanned
              ? (root.overallStatus === "fail" ? "Compromised"
                 : root.overallStatus === "warn" ? "With warnings"
                 : "All clean") + " · " + root.relTime(root.securityStatus.checked)
              : "no scan yet"
            foreground: root.foreground
            fontFamily: Style.font.family

            iconComponent: Component {
              Item {
                width: heroBlock.heroIconSlot
                height: Style.font.display
                Text {
                  anchors.centerIn: parent
                  text: root.securityScanning ? "…" : "󰒙"
                  color: root.badgeColor()
                  font.family: Style.font.family
                  font.pixelSize: Style.font.display
                }
              }
            }

            trailingControl: Component {
              Row {
                spacing: Style.spacing.xs
                PanelActionButton {
                  iconText: "󰋚"
                  foreground: root.foreground
                  tooltipText: "Scan history"
                  onClicked: root.showHistory = true
                }
                PanelActionButton {
                  iconText: "󰒓"
                  foreground: root.foreground
                  tooltipText: "Scanner setup"
                  onClicked: root.showSettings = true
                }
              }
            }
          }
        }

        // Next-scan / skipped-due-to-gaming line -- only when there is
        // something to say. Same indent as the hero's title: heroIconSlot
        // plus the 14px margin PanelHero applies internally between icon
        // and labels.
        Text {
          visible: root.nextScanText !== ""
          anchors.left: parent.left
          anchors.leftMargin: heroBlock.heroIconSlot + Style.space(14)
          anchors.right: parent.right
          text: root.nextScanText
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.42)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.Wrap
        }
      }

      // AUR-Malware results -- the separator is a sibling of the content
      // column (not nested inside it), matching how Omarchy's own panels
      // (e.g. Network's "DNS PROVIDER" section) separate a section from the
      // previous one with the view's larger spacing, while keeping a
      // tighter spacing for title→summary→button within the section.
      PanelSeparator { visible: root.aurAvailable; foreground: root.foreground }
      Column {
        visible: root.aurAvailable
        width: parent.width
        spacing: Style.space(10)
        Item {
          width: parent.width
          height: Math.max(aurH.implicitHeight, aurSt.implicitHeight)
          PanelSectionHeader { id: aurH; anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter; foreground: root.foreground; text: "AUR-MALWARE" }
          Text { id: aurSt; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: root.everScanned ? root.statusLabel(root.aur.status) : "—"; color: root.statusColor(root.aur.status); font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true }
        }
        Text { width: parent.width; text: root.everScanned ? (root.aur.summary || "no data") : "no scan yet"; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.8); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
        Rectangle {
          visible: root.aurIssues.length > 0
          width: parent.width
          height: Style.spacing.controlHeight
          radius: Style.cornerRadius
          color: aurDetailMa.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
          border.color: aurDetailMa.containsMouse ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
          border.width: 1
          Behavior on color { ColorAnimation { duration: 120 } }
          Text { anchors.centerIn: parent; text: "View detail"; color: aurDetailMa.containsMouse ? Color.accent : root.foreground; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
          MouseArea { id: aurDetailMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.showAurDetail = true }
        }
      }

      // Persistence results -- always available, no install step.
      PanelSeparator { visible: root.persistenceAvailable; foreground: root.foreground }
      Column {
        visible: root.persistenceAvailable
        width: parent.width
        spacing: Style.space(10)
        Item {
          width: parent.width
          height: Math.max(persH.implicitHeight, persSt.implicitHeight)
          PanelSectionHeader { id: persH; anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter; foreground: root.foreground; text: "PERSISTENCE" }
          Text { id: persSt; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: root.everScanned ? root.statusLabel(root.persistence.status) : "—"; color: root.statusColor(root.persistence.status); font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true }
        }
        Text { width: parent.width; text: root.everScanned ? (root.persistence.summary || "no data") : "no scan yet"; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.8); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
        Rectangle {
          visible: root.persistenceIssues.length > 0
          width: parent.width
          height: Style.spacing.controlHeight
          radius: Style.cornerRadius
          color: persDetailMa.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
          border.color: persDetailMa.containsMouse ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
          border.width: 1
          Behavior on color { ColorAnimation { duration: 120 } }
          Text { anchors.centerIn: parent; text: "View detail"; color: persDetailMa.containsMouse ? Color.accent : root.foreground; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
          MouseArea { id: persDetailMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.showPersistenceDetail = true }
        }
      }

      // Bumblebee results
      PanelSeparator { visible: root.bbAvailable; foreground: root.foreground }
      Column {
        visible: root.bbAvailable
        width: parent.width
        spacing: Style.space(10)
        Item {
          width: parent.width
          height: Math.max(bbH.implicitHeight, bbSt.implicitHeight)
          PanelSectionHeader { id: bbH; anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter; foreground: root.foreground; text: "BUMBLEBEE" }
          Text { id: bbSt; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: root.everScanned ? root.statusLabel(root.bb.status) : "—"; color: root.statusColor(root.bb.status); font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true }
        }
        Text { width: parent.width; text: root.everScanned ? (root.bb.summary || "no data") : "no scan yet"; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.8); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
      }

      // No active scanners (bumblebee/AUR disabled -- persistence always
      // counts as active, so this block is almost never seen)
      PanelSeparator { visible: !root.aurAvailable && !root.bbAvailable && !root.persistenceAvailable; foreground: root.foreground }
      Column {
        visible: !root.aurAvailable && !root.bbAvailable && !root.persistenceAvailable
        width: parent.width
        spacing: Style.space(10)
        Text {
          width: parent.width
          text: "No system scanners active.\nClick ⚙ to install or enable scanners."
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.52)
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
        }
      }

      // Scanning a single project folder -- a separate action from the
      // general status above, so it goes before "Scan now", not right
      // next to it.
      PanelSeparator { visible: root.bunCheckEnabled || root.bbAvailable; foreground: root.foreground }
      Column {
        visible: root.bunCheckEnabled || root.bbAvailable
        width: parent.width
        spacing: Style.space(10)
        PanelSectionHeader { foreground: root.foreground; text: "SCAN A PROJECT FOLDER" }
        Row {
          width: parent.width
          spacing: root.bunCheckEnabled && root.bbAvailable ? Style.spacing.lg : 0
          Rectangle {
            visible: root.bunCheckEnabled
            width: root.bunCheckEnabled && root.bbAvailable ? (parent.width - Style.spacing.lg) / 2 : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bunMa.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
            border.color: bunMa.containsMouse ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text { anchors.centerIn: parent; text: "bun-check…"; color: bunMa.containsMouse ? Color.accent : root.foreground; font.family: Style.font.family; font.pixelSize: Style.font.caption }
            MouseArea { id: bunMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: { root.close(); bunCheckRunner.running = false; bunCheckRunner.running = true } }
          }
          Rectangle {
            visible: root.bbAvailable
            width: root.bunCheckEnabled && root.bbAvailable ? (parent.width - Style.spacing.lg) / 2 : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bbMa.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
            border.color: bbMa.containsMouse ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text { anchors.centerIn: parent; text: "bumblebee…"; color: bbMa.containsMouse ? Color.accent : root.foreground; font.family: Style.font.family; font.pixelSize: Style.font.caption }
            MouseArea { id: bbMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: { root.close(); bumblebeeRunner.running = false; bumblebeeRunner.running = true } }
          }
        }
      }

      // "Scan now" -- the final action, separate from everything above it.
      // Same Style.spacing.lg gap from mainCol that separates the rest of
      // the sections from each other, no special treatment.
      PanelSeparator { visible: root.anyScanner; foreground: root.foreground }
      Column {
        visible: root.anyScanner
        width: parent.width
        Rectangle {
          width: parent.width
          height: Style.spacing.controlHeight
          radius: Style.cornerRadius
          opacity: root.securityScanning ? 0.5 : 1.0
          color: (scanMa.containsMouse && !root.securityScanning) ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
          border.color: (scanMa.containsMouse && !root.securityScanning) ? Color.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
          border.width: 1
          Behavior on color { ColorAnimation { duration: 120 } }
          Text { anchors.centerIn: parent; text: root.securityScanning ? "Scanning…" : "Scan now"; color: (scanMa.containsMouse && !root.securityScanning) ? Color.accent : root.foreground; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
          MouseArea { id: scanMa; anchors.fill: parent; hoverEnabled: true; enabled: !root.securityScanning; cursorShape: root.securityScanning ? Qt.ArrowCursor : Qt.PointingHandCursor; onClicked: root.rescan() }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // AUR-Malware detail view — what failed/warned, and why. The main view
    // only ever had room for a status word + a one-line summary; this is
    // where "which check, and what did it actually find" lives instead of
    // dumping it into that summary line.
    // ═══════════════════════════════════════════════════════════════════════
    IssueDetailView {
      id: aurDetailCol
      visible: root.showAurDetail
      headerTitle: "AUR-MALWARE DETAIL"
      groups: root.aurGroups
      blockKey: "aur_malware"
      onBackClicked: root.showAurDetail = false
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Persistence detail view — same pattern as the AUR-Malware one.
    // ═══════════════════════════════════════════════════════════════════════
    IssueDetailView {
      id: persistenceDetailCol
      visible: root.showPersistenceDetail
      headerTitle: "PERSISTENCE DETAIL"
      groups: root.persistenceGroups
      blockKey: "persistence"
      onBackClicked: root.showPersistenceDetail = false
    }

    // ═══════════════════════════════════════════════════════════════════════
    // History view — a compact record of past scans, not just the latest
    // one. Without this, a one-off finding that is no longer present leaves
    // no trace that it ever happened.
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: historyCol
      visible: root.showHistory
      width: panelFlick.width
      spacing: Style.space(12)

      Item {
        width: parent.width
        height: Style.spacing.xxl
        PanelActionButton {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰁍"
          foreground: root.foreground
          tooltipText: "Back"
          onClicked: root.showHistory = false
        }
        Text {
          anchors.centerIn: parent
          text: "SCAN HISTORY"
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.7)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }
      }

      Text {
        visible: root.scanHistoryRecent.length === 0
        width: parent.width
        text: "No history yet — it builds up with each scan."
        color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.52)
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
      }

      Repeater {
        model: root.scanHistoryRecent
        delegate: Column {
          required property var modelData
          width: historyCol.width
          spacing: Style.spacing.xxs
          PanelSeparator { foreground: root.foreground }
          Item {
            width: parent.width
            height: Math.max(histTime.implicitHeight, histSt.implicitHeight)
            Text {
              id: histTime
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              text: root.relTime(modelData.checked)
              color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.6)
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
            Text {
              id: histSt
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              text: root.statusLabel(root.historyEntryStatus(modelData))
              color: root.statusColor(root.historyEntryStatus(modelData))
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: true
            }
          }
          Text {
            width: parent.width
            text: root.historyEntrySummary(modelData)
            color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.75)
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Settings view
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: settingsCol
      visible: root.showSettings
      width: panelFlick.width
      spacing: Style.space(12)

      // Header: back + title
      Item {
        width: parent.width
        height: Style.spacing.xxl
        PanelActionButton {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰁍"
          foreground: root.foreground
          tooltipText: "Back"
          onClicked: root.showSettings = false
        }
        Text {
          anchors.centerIn: parent
          text: "SCANNER SETUP"
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.7)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }
      }

      ScannerRow {
        title: "AUR-MALWARE"
        installed: root.aurInstalled
        userEnabled: root.aurUserEnabled
        opBusy: root.aurOpBusy
        opMsg: root.aurOpMsg
        opError: root.aurOpError
        onInstallClicked:   root.installAur()
        onUninstallClicked: root.uninstallAur()
        onToggleClicked:    root.toggleAur()
      }

      ScannerRow {
        title: "BUMBLEBEE"
        installed: root.bbInstalled
        userEnabled: root.bbUserEnabled
        opBusy: root.bbOpBusy
        opMsg: root.bbOpMsg
        opError: root.bbOpError
        onInstallClicked:   root.installBB()
        onUninstallClicked: root.uninstallBB()
        onToggleClicked:    root.toggleBB()
      }

      ScannerRow {
        title: "BUN-CHECK"
        installed: root.bunInstalled
        userEnabled: root.bunUserEnabled
        opBusy: root.bunOpBusy
        opMsg: root.bunOpMsg
        opError: root.bunOpError
        onInstallClicked:   root.installBun()
        onUninstallClicked: root.uninstallBun()
        onToggleClicked:    root.toggleBun()
      }

      PanelSeparator { foreground: root.foreground }
      Column {
        width: parent.width
        spacing: Style.space(10)
        PanelSectionHeader { foreground: root.foreground; text: "PERSISTENCE" }
        Text {
          width: parent.width
          text: "Always active — checks app launchers, user systemd units and crontab. No install step needed."
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.52)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          wrapMode: Text.Wrap
        }
      }

      Item { width: parent.width; height: Style.spacing.xs }
    }
      }
    }
  }
}
