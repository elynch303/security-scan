import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Security-status badge for Omarchy bars.
//
// Main view  — live scan results from ~/.cache/qs-security-status.json
//            — per-scanner sections hidden when not installed or toggled off
//            — gear icon opens Settings view
//
// Settings view — install / uninstall each scanner with one click
//               — toggle each scanner on/off (widget-side preference)
//               — preferences persisted to ~/.config/qs-security/settings.json
//
// Scanners:
//   AUR-Malware  git clone to /local/applications/AUR-Malware (or QS_SEC_AUR_MALWARE)
//   bumblebee    go install github.com/anchore/bumblebee@latest
//   bun-check    bundled script → ~/.local/bin/qs-bun-check-oneshot.sh
BarWidget {
  id: root
  moduleName: "local.security-scan"

  // ── scan state ──────────────────────────────────────────────────────────
  property var securityStatus: ({})
  property bool securityScanning: false

  readonly property var aur: securityStatus.aur_malware || ({})
  readonly property var bb:  securityStatus.bumblebee   || ({})
  readonly property bool everScanned: !!securityStatus.checked

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
  readonly property bool anyScanner:      aurAvailable || bbAvailable

  // ── settings panel UI state ─────────────────────────────────────────────
  property bool showSettings: false
  property bool showDetail: false
  property string aurDetailText: ""

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
    return ov ? ov : "/local/applications/AUR-Malware/check-atomic-arch_new.sh"
  }
  readonly property string aurMalwareDir: {
    var p = root.aurEffectivePath
    var i = p.lastIndexOf("/")
    return i > 0 ? p.substring(0, i) : "/local/applications/AUR-Malware"
  }

  readonly property string bunDst: home + "/.local/bin/qs-bun-check-oneshot.sh"
  readonly property string bunSrc: home + "/.config/omarchy/plugins/io.github.elynch303.security-scan/qs-bun-check-oneshot.sh"
  readonly property string settingsPath: home + "/.config/qs-security/settings.json"

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
    id: aurDetailFile
    path: home + "/.cache/qs-security-aur-detail.txt"
    watchChanges: true
    onFileChanged: aurDetailFile.reload()
    onLoaded: root.aurDetailText = aurDetailFile.text()
    onLoadFailed: root.aurDetailText = ""
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
    settingsFile.reload()
    aurDetailFile.reload()
    bunProbe.reload()
    aurProbe.reload()
    bbProbe.reload()
    startupScanTimer.start()
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
    onExited: statusFile.reload()
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

  // Auto-scan once 10s after startup so the bar never shows a stale result on login.
  Timer {
    id: startupScanTimer
    interval: 10000
    repeat: false
    onTriggered: if (root.anyScanner) root.rescan()
  }

  // Periodic background rescan every 30 minutes.
  Timer {
    id: periodicScanTimer
    interval: 1800000
    repeat: true
    running: root.anyScanner
    onTriggered: root.rescan()
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
      "mkdir -p \"$(dirname \"$0\")\" && git clone https://github.com/Atomic-Arch/AUR-Malware.git \"$0\"",
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
      "GOBIN=$HOME/.local/bin go install github.com/perplexityai/bumblebee@latest"
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
    return worst === 2 ? "fail" : (worst === 1 ? "warn" : "clean")
  }

  function badgeColor() {
    if (!root.anyScanner) return Color.accent
    if (!root.everScanned) return Color.accent
    if (root.overallStatus === "fail") return Color.urgent
    if (root.overallStatus === "warn") return "#e8a33d"
    return Color.accent
  }

  function statusColor(s) {
    if (s === "fail" || s === "error") return Color.urgent
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
      detail.open = !detail.open
      if (!detail.open) root.showSettings = false
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
  PopupCard {
    id: detail
    anchorItem: button
    bar: root.bar
    owner: root
    contentWidth: Style.space(300)
    contentHeight: (root.showSettings ? settingsCol.implicitHeight : root.showDetail ? detailCol.implicitHeight : mainCol.implicitHeight) + padding * 2

    onOpenChanged: if (!open) { root.showSettings = false; root.showDetail = false }

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
      color: abMa.containsMouse ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
      border.width: 1
      border.color: destructive
        ? Qt.rgba(Color.urgent.r, Color.urgent.g, Color.urgent.b, abMa.containsMouse ? 0.65 : 0.3)
        : (abMa.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15))
      Behavior on color { ColorAnimation { duration: 120 } }
      Text {
        anchors.centerIn: parent
        text: ab.label
        color: ab.destructive
          ? (abMa.containsMouse ? Color.urgent : Qt.rgba(Color.urgent.r, Color.urgent.g, Color.urgent.b, 0.7))
          : (abMa.containsMouse ? Color.accent : Color.popups.text)
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

      PanelSeparator { foreground: Color.popups.text }

      Item {
        width: parent.width
        height: srHeader.implicitHeight + Style.spacing.xs * 2

        PanelSectionHeader {
          id: srHeader
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          foreground: Color.popups.text
          text: sr.title
        }

        ToggleSwitch {
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: sr.installed
          checked: sr.userEnabled
          busy: sr.opBusy
          foreground: Color.popups.text
          onToggled: sr.toggleClicked()
        }

        Text {
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: !sr.installed
          text: "Not installed"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.42)
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
          ? Color.urgent
          : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.58)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        wrapMode: Text.Wrap
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Main view
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: mainCol
      visible: !root.showSettings
      width: detail.contentWidth - detail.padding * 2
      spacing: Style.spacing.lg

      // Header: title + timestamp + gear
      Item {
        width: parent.width
        height: Style.spacing.xxl
        Text {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          text: "Security"
          color: Color.popups.text
          font.family: Style.font.family
          font.pixelSize: Style.font.subtitle
          font.bold: true
        }
        Text {
          anchors.right: gearBtn.left
          anchors.rightMargin: Style.spacing.sm
          anchors.verticalCenter: parent.verticalCenter
          text: root.everScanned ? root.relTime(root.securityStatus.checked) : "never scanned"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.52)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
        PanelActionButton {
          id: gearBtn
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰒓"
          foreground: Color.popups.text
          tooltipText: "Scanner setup"
          onClicked: root.showSettings = true
        }
      }

      // AUR-Malware results
      Column {
        visible: root.aurAvailable
        width: parent.width
        spacing: Style.spacing.xs
        PanelSeparator { foreground: Color.popups.text }
        Item {
          width: parent.width
          height: Math.max(aurH.implicitHeight, aurSt.implicitHeight)
          PanelSectionHeader { id: aurH; anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter; foreground: Color.popups.text; text: "AUR-MALWARE" }
          Text { id: aurSt; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: root.everScanned ? root.statusLabel(root.aur.status) : "—"; color: root.statusColor(root.aur.status); font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true }
        }
        Text { width: parent.width; text: root.everScanned ? (root.aur.summary || "no data") : "no scan yet"; color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.8); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
        Text {
          visible: root.everScanned && root.aurDetailText !== ""
          width: parent.width
          horizontalAlignment: Text.AlignRight
          text: "full output ›"
          color: aurDetailLink.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.35)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          Behavior on color { ColorAnimation { duration: 80 } }
          MouseArea {
            id: aurDetailLink
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { root.showDetail = true; detailFlickable.contentY = 0 }
          }
        }
      }

      // Bumblebee results
      Column {
        visible: root.bbAvailable
        width: parent.width
        spacing: Style.spacing.xs
        PanelSeparator { foreground: Color.popups.text }
        Item {
          width: parent.width
          height: Math.max(bbH.implicitHeight, bbSt.implicitHeight)
          PanelSectionHeader { id: bbH; anchors.left: parent.left; anchors.verticalCenter: parent.verticalCenter; foreground: Color.popups.text; text: "BUMBLEBEE" }
          Text { id: bbSt; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: root.everScanned ? root.statusLabel(root.bb.status) : "—"; color: root.statusColor(root.bb.status); font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true }
        }
        Text { width: parent.width; text: root.everScanned ? (root.bb.summary || "no data") : "no scan yet"; color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.8); font.family: Style.font.family; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
      }

      // No active scanners
      Column {
        visible: !root.aurAvailable && !root.bbAvailable
        width: parent.width
        spacing: Style.spacing.xs
        PanelSeparator { foreground: Color.popups.text }
        Text {
          width: parent.width
          text: "No system scanners active.\nClick ⚙ to install or enable scanners."
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.52)
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
        }
      }

      // One-shot project scan
      Column {
        visible: root.bunCheckEnabled || root.bbAvailable
        width: parent.width
        spacing: Style.spacing.md
        PanelSeparator { foreground: Color.popups.text }
        PanelSectionHeader { foreground: Color.popups.text; text: "SCAN A PROJECT FOLDER" }
        Row {
          width: parent.width
          spacing: root.bunCheckEnabled && root.bbAvailable ? Style.spacing.lg : 0
          Rectangle {
            visible: root.bunCheckEnabled
            width: root.bunCheckEnabled && root.bbAvailable ? (parent.width - Style.spacing.lg) / 2 : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bunMa.containsMouse ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
            border.color: bunMa.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text { anchors.centerIn: parent; text: "bun-check…"; color: bunMa.containsMouse ? Color.accent : Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.caption }
            MouseArea { id: bunMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: { detail.open = false; bunCheckRunner.running = false; bunCheckRunner.running = true } }
          }
          Rectangle {
            visible: root.bbAvailable
            width: root.bunCheckEnabled && root.bbAvailable ? (parent.width - Style.spacing.lg) / 2 : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bbMa.containsMouse ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
            border.color: bbMa.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text { anchors.centerIn: parent; text: "bumblebee…"; color: bbMa.containsMouse ? Color.accent : Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.caption }
            MouseArea { id: bbMa; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: { detail.open = false; bumblebeeRunner.running = false; bumblebeeRunner.running = true } }
          }
        }
      }

      // Scan now
      Column {
        visible: root.anyScanner
        width: parent.width
        PanelSeparator { foreground: Color.popups.text }
        Rectangle {
          width: parent.width
          height: Style.spacing.controlHeight
          radius: Style.cornerRadius
          opacity: root.securityScanning ? 0.5 : 1.0
          color: (scanMa.containsMouse && !root.securityScanning) ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
          border.color: (scanMa.containsMouse && !root.securityScanning) ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15)
          border.width: 1
          Behavior on color { ColorAnimation { duration: 120 } }
          Text { anchors.centerIn: parent; text: root.securityScanning ? "Scanning…" : "Scan now"; color: (scanMa.containsMouse && !root.securityScanning) ? Color.accent : Color.popups.text; font.family: Style.font.family; font.pixelSize: Style.font.bodySmall }
          MouseArea { id: scanMa; anchors.fill: parent; hoverEnabled: true; enabled: !root.securityScanning; cursorShape: root.securityScanning ? Qt.ArrowCursor : Qt.PointingHandCursor; onClicked: root.rescan() }
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Settings view
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: settingsCol
      visible: root.showSettings
      width: detail.contentWidth - detail.padding * 2
      spacing: Style.spacing.md

      // Header: back + title
      Item {
        width: parent.width
        height: Style.spacing.xxl
        PanelActionButton {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰁍"
          foreground: Color.popups.text
          tooltipText: "Back"
          onClicked: root.showSettings = false
        }
        Text {
          anchors.centerIn: parent
          text: "SCANNER SETUP"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.7)
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

      Item { width: parent.width; height: Style.spacing.xs }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Detail view — full AUR scan output
    // ═══════════════════════════════════════════════════════════════════════
    Column {
      id: detailCol
      visible: root.showDetail
      width: detail.contentWidth - detail.padding * 2
      spacing: Style.spacing.sm

      Item {
        width: parent.width
        height: Style.spacing.xxl
        PanelActionButton {
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          iconText: "󰁍"
          foreground: Color.popups.text
          tooltipText: "Back"
          onClicked: root.showDetail = false
        }
        Text {
          anchors.centerIn: parent
          text: "AUR SCAN OUTPUT"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.7)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }
      }

      PanelSeparator { foreground: Color.popups.text }

      Flickable {
        id: detailFlickable
        width: parent.width
        height: Style.space(380)
        contentWidth: width
        contentHeight: detailOutputText.implicitHeight
        clip: true

        Text {
          id: detailOutputText
          width: detailFlickable.width
          text: root.aurDetailText !== "" ? root.aurDetailText : "No scan output yet.\nTrigger a scan first."
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.82)
          font.family: "monospace"
          font.pixelSize: Style.font.caption
          wrapMode: Text.WrapAnywhere
        }
      }

      Item { width: parent.width; height: Style.spacing.xs }
    }
  }
}
