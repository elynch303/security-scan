import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Security-status badge, installable on any Omarchy bar. Read-only mirror of
// ~/.cache/qs-security-status.json, written by ~/.local/bin/qs-security-scan.sh
// (systemd timer, every 6h). Each of the three scanner sections is optional —
// the widget reads the "available" field written by the scan script and hides
// sections for tools that are not installed.
//
// Scanners:
//   AUR-Malware  — system IOC scan (check-atomic-arch); configured via
//                  QS_SEC_AUR_MALWARE env or /local/applications/AUR-Malware/
//   bumblebee    — package inventory scan; install via `go install bumblebee@latest`
//   bun-check    — per-project dev-env scan; one-shot only (~/.local/bin/qs-bun-check-oneshot.sh)
BarWidget {
  id: root
  moduleName: "local.security-scan"

  property var securityStatus: ({})
  property bool securityScanning: false
  property bool bunCheckAvailable: false

  readonly property var aur: securityStatus.aur_malware || ({})
  readonly property var bb: securityStatus.bumblebee || ({})
  readonly property bool everScanned: !!securityStatus.checked

  readonly property bool aurAvailable: aur.available === true
  readonly property bool bbAvailable: bb.available === true
  readonly property bool anyScanner: aurAvailable || bbAvailable

  readonly property string overallStatus: {
    var severity = { fail: 2, error: 2, warn: 1, findings: 1 }
    var worst = 0
    if (aurAvailable) worst = Math.max(worst, severity[aur.status] || 0)
    if (bbAvailable) worst = Math.max(worst, severity[bb.status] || 0)
    return worst === 2 ? "fail" : (worst === 1 ? "warn" : "clean")
  }

  function badgeColor() {
    if (!root.anyScanner) return Color.accent
    if (!root.everScanned) return Color.accent
    if (root.overallStatus === "fail") return Color.urgent
    if (root.overallStatus === "warn") return "#e8a33d"
    return Color.accent
  }

  visible: true
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  FileView {
    id: statusFile
    path: Quickshell.env("HOME") + "/.cache/qs-security-status.json"
    watchChanges: true
    onFileChanged: statusFile.reload()
    onLoaded: {
      try { root.securityStatus = JSON.parse(statusFile.text()) } catch (e) { /* keep last good value */ }
      root.securityScanning = false
    }
    onLoadFailed: {}   // first boot before timer's first run: no badge, no notice
  }

  FileView {
    id: bunCheckProbe
    path: Quickshell.env("HOME") + "/.local/bin/qs-bun-check-oneshot.sh"
    onLoaded: root.bunCheckAvailable = true
    onLoadFailed: root.bunCheckAvailable = false
  }

  Component.onCompleted: { statusFile.reload(); bunCheckProbe.reload() }

  Process {
    id: rescanProc
    command: [Quickshell.env("HOME") + "/.local/bin/qs-security-scan.sh"]
    running: false
    onExited: statusFile.reload()
  }

  function rescan() {
    root.securityScanning = true
    rescanProc.running = false
    rescanProc.running = true
  }

  // unstick the button if a manual scan hangs (real scans take ~10s)
  Timer {
    interval: 60000
    running: root.securityScanning
    onTriggered: { root.securityScanning = false; rescanProc.running = false }
  }

  function statusColor(s) {
    if (s === "fail" || s === "error") return Color.urgent
    if (s === "warn" || s === "findings") return "#e8a33d"
    return Color.accent
  }
  function statusLabel(s) {
    if (s === "clean") return "CLEAN"
    if (s === "warn") return "WARNINGS"
    if (s === "fail") return "COMPROMISED"
    if (s === "findings") return "FINDINGS"
    if (s === "error") return "ERROR"
    return "UNKNOWN"
  }
  function relTime(iso) {
    if (!iso) return ""
    var then = new Date(iso).getTime()
    if (isNaN(then)) return ""
    var mins = Math.max(0, Math.round((Date.now() - then) / 60000))
    if (mins < 1) return "just now"
    if (mins < 60) return mins + "m ago"
    var hrs = Math.round(mins / 60)
    if (hrs < 24) return hrs + "h ago"
    return Math.round(hrs / 24) + "d ago"
  }

  readonly property string tooltipText: {
    if (!root.anyScanner && !root.bunCheckAvailable) return "No scanners configured\nClick for setup info"
    if (root.securityScanning) return "Scanning…"
    if (!root.everScanned) return "Security scan pending\nClick to view details"
    var parts = []
    if (root.aurAvailable && root.aur.status) parts.push("AUR-Malware: " + (root.aur.summary || root.aur.status))
    if (root.bbAvailable && root.bb.status) parts.push("bumblebee: " + (root.bb.summary || root.bb.status))
    return parts.join("\n") + "\nClick to view details"
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.securityScanning ? "…" : "󰒙"   // md-shield_outline (Nerd Font, U+F0499)
    slotSize: Style.bar.statusSlot
    fontSize: Style.bar.iconFont
    tooltipText: root.tooltipText
    activeColor: root.badgeColor()
    active: root.anyScanner || root.bunCheckAvailable
    onPressed: detail.open = !detail.open
  }

  // detached (setsid -f) so the picker + floating terminal survive the popup closing
  Process {
    id: bunCheckRunner
    command: ["setsid", "-f", "bash", Quickshell.env("HOME") + "/.local/bin/qs-bun-check-oneshot.sh"]
  }
  Process {
    id: bumblebeeRunner
    command: ["setsid", "-f", "bash", Quickshell.env("HOME") + "/.local/bin/qs-bumblebee-oneshot.sh"]
  }

  PopupCard {
    id: detail
    anchorItem: button
    bar: root.bar
    owner: root
    contentWidth: Style.space(300)
    contentHeight: col.implicitHeight + padding * 2

    Column {
      id: col
      width: detail.contentWidth - detail.padding * 2
      spacing: Style.spacing.lg

      // Header
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
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: root.everScanned ? root.relTime(root.securityStatus.checked) : "never scanned"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.55)
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }

      // AUR-Malware section — hidden when scanner is not installed
      Column {
        visible: root.aurAvailable
        width: parent.width
        spacing: Style.spacing.xs

        PanelSeparator { foreground: Color.popups.text }

        Item {
          width: parent.width
          height: Math.max(aurHeader.implicitHeight, aurStatus.implicitHeight)
          PanelSectionHeader {
            id: aurHeader
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            foreground: Color.popups.text
            text: "AUR-MALWARE"
          }
          Text {
            id: aurStatus
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: root.everScanned ? root.statusLabel(root.aur.status) : "—"
            color: root.statusColor(root.aur.status)
            font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true
          }
        }
        Text {
          width: parent.width
          text: root.everScanned ? (root.aur.summary || "no data") : "no scan yet"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.8)
          font.family: Style.font.family; font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
        }
      }

      // Bumblebee section — hidden when scanner is not installed
      Column {
        visible: root.bbAvailable
        width: parent.width
        spacing: Style.spacing.xs

        PanelSeparator { foreground: Color.popups.text }

        Item {
          width: parent.width
          height: Math.max(bbHeader.implicitHeight, bbStatus.implicitHeight)
          PanelSectionHeader {
            id: bbHeader
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            foreground: Color.popups.text
            text: "BUMBLEBEE"
          }
          Text {
            id: bbStatus
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: root.everScanned ? root.statusLabel(root.bb.status) : "—"
            color: root.statusColor(root.bb.status)
            font.family: Style.font.family; font.pixelSize: Style.font.caption; font.bold: true
          }
        }
        Text {
          width: parent.width
          text: root.everScanned ? (root.bb.summary || "no data") : "no scan yet"
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.8)
          font.family: Style.font.family; font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
        }
      }

      // "No scanners" notice — shown only when neither system scanner is installed
      Column {
        visible: !root.aurAvailable && !root.bbAvailable
        width: parent.width
        spacing: Style.spacing.xs

        PanelSeparator { foreground: Color.popups.text }

        Text {
          width: parent.width
          text: "No system scanners configured.\n\nInstall AUR-Malware or bumblebee\nand wire them into qs-security-scan.sh."
          color: Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.55)
          font.family: Style.font.family; font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
        }
      }

      // One-shot project-scan section — hidden when bun-check is not installed
      // (bumblebee project-scan button also shown here when bumblebee is installed)
      Column {
        visible: root.bunCheckAvailable || root.bbAvailable
        width: parent.width
        spacing: Style.spacing.md

        PanelSeparator { foreground: Color.popups.text }

        PanelSectionHeader { foreground: Color.popups.text; text: "SCAN A PROJECT FOLDER" }

        Row {
          width: parent.width
          spacing: root.bunCheckAvailable && root.bbAvailable ? Style.spacing.lg : 0

          Rectangle {
            visible: root.bunCheckAvailable
            width: root.bunCheckAvailable && root.bbAvailable
              ? (parent.width - Style.spacing.lg) / 2
              : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bunMa.containsMouse ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
            border.color: bunMa.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text {
              anchors.centerIn: parent
              text: "bun-check…"
              color: bunMa.containsMouse ? Color.accent : Color.popups.text
              font.family: Style.font.family; font.pixelSize: Style.font.caption
            }
            MouseArea {
              id: bunMa
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: { detail.open = false; bunCheckRunner.running = false; bunCheckRunner.running = true }
            }
          }

          Rectangle {
            visible: root.bbAvailable
            width: root.bunCheckAvailable && root.bbAvailable
              ? (parent.width - Style.spacing.lg) / 2
              : parent.width
            height: Style.spacing.controlHeight
            radius: Style.cornerRadius
            color: bbMa.containsMouse ? Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.08) : "transparent"
            border.color: bbMa.containsMouse ? Color.accent : Qt.rgba(Color.popups.text.r, Color.popups.text.g, Color.popups.text.b, 0.15)
            border.width: 1
            Behavior on color { ColorAnimation { duration: 120 } }
            Text {
              anchors.centerIn: parent
              text: "bumblebee…"
              color: bbMa.containsMouse ? Color.accent : Color.popups.text
              font.family: Style.font.family; font.pixelSize: Style.font.caption
            }
            MouseArea {
              id: bbMa
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: { detail.open = false; bumblebeeRunner.running = false; bumblebeeRunner.running = true }
            }
          }
        }
      }

      // Scan-now button — only shown when at least one system scanner is configured
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
          Text {
            anchors.centerIn: parent
            text: root.securityScanning ? "Scanning…" : "Scan now"
            color: (scanMa.containsMouse && !root.securityScanning) ? Color.accent : Color.popups.text
            font.family: Style.font.family; font.pixelSize: Style.font.bodySmall
          }
          MouseArea {
            id: scanMa
            anchors.fill: parent
            hoverEnabled: true
            enabled: !root.securityScanning
            cursorShape: root.securityScanning ? Qt.ArrowCursor : Qt.PointingHandCursor
            onClicked: root.rescan()
          }
        }
      }
    }
  }
}
