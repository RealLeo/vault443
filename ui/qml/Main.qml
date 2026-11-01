import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

ApplicationWindow {
    id: appWindow
    visible: true
    width: Math.round(944 * initialScale)
    height: Math.round(960 * initialScale)
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height
    flags: Qt.Window | Qt.FramelessWindowHint
    color: "transparent"
    title: "Vault 443"
    property var snap: backend.snapshot
    property var runtime: snap.runtime || ({})
    property var traffic: snap.traffic || ({})
    property bool trafficAvailable: backend.online && !snap.busyByOtherUser && traffic.valid === true
    property var profiles: backend.profiles
    property string activeId: snap.activeProfileId || ""
    property string bodyFont: condensedFont.status === FontLoader.Ready ? condensedFont.name : "DejaVu Sans Condensed"
    property string monoFont: monoLoader.status === FontLoader.Ready ? monoLoader.name : "DejaVu Sans Mono"
    property int tick: 0
    property var selectedProfile: ({})
    property var selectedSubscription: ({})
    property var diagnosticProfile: ({})
    property var operation: backend.connectionRequest.action ? backend.connectionRequest : (snap.operation || ({}))
    property bool cleaning: operation.action === "disconnect" && operation.stage !== "disconnected"
    property bool switching: !!operation.previousProfileId && !switchFinished(operation)
    function switchFinished(op) { return op.stage === "switch_failed" || op.stage === "switch_cancelled" }
    property string pendingOperation: ""
    property string profileIconId: "antenna"
    property string iconTargetId: ""
    property string iconTarget: "profile"
    property bool logHistoryMode: false
    property bool logFollowEnd: true
    property real logSavedPosition: 0
    property int subscriptionFailureCount: -1
    property bool subscriptionRefreshDone: false
    property bool vpnBindingSaved: false
    function localizedMessage(value) { i18n.language; return i18n.serviceMessage(value || "") }
    function bytes(value) {
        i18n.language
        var n = Math.max(0, Number(value || 0))
        var units = [qsTr("%1 B"), qsTr("%1 KB"), qsTr("%1 MB"), qsTr("%1 GB"), qsTr("%1 TB"), qsTr("%1 PB"), qsTr("%1 EB")]
        var unit = 0
        while (n >= 1024 && unit < units.length - 1) { n /= 1024; unit++ }
        var decimals = unit > 0 && n < 100 ? 1 : 0
        return units[unit].arg(n.toFixed(decimals).replace(".", i18n.language === "ru" ? "," : "."))
    }
    function sessionDuration() {
        if (!trafficAvailable) return "—"
        var seconds = Math.max(0, Math.floor(Number(traffic.durationSeconds || 0)))
        function padded(n) { return n < 10 ? "0" + n : String(n) }
        return padded(Math.floor(seconds / 3600)) + ":" + padded(Math.floor(seconds / 60) % 60) + ":" + padded(seconds % 60)
    }
    function trafficText(value, rate) {
        i18n.language
        if (!trafficAvailable) return "—"
        return rate ? qsTr("%1/s").arg(bytes(value)) : bytes(value)
    }
    function fullTraffic(value, rate) {
        i18n.language
        if (!trafficAvailable) return "—"
        var n = Math.max(0, Number(value || 0))
        var text = n.toFixed(rate && n % 1 ? 1 : 0).replace(".", i18n.language === "ru" ? "," : ".")
        var amount = qsTr("%1 B").arg(text)
        if (n > 9007199254740991) amount = "≈ " + amount
        return rate ? qsTr("%1/s").arg(amount) : amount
    }
    function trafficExplanation() {
        i18n.language
        if (!backend.online) return qsTr("Service unavailable — traffic statistics are unknown.")
        if (snap.busyByOtherUser) return qsTr("Traffic statistics belong to another user.")
        if (!traffic.valid) return qsTr("Waiting for a reliable TUN traffic measurement.")
        return qsTr("Main VPN traffic (VLESS, Trojan or Shadowsocks/Outline). IP traffic through its TUN, including internal service requests. Work VPNs and encrypted transport overhead are excluded.")
    }
    function stageName(stage, action) {
        i18n.language
        var names = {preparing_switch:qsTr("Preparing new profile"), switching_profile:qsTr("Switching VPN"), restoring_previous:qsTr("Restoring previous VPN"), requested: action === "disconnect" ? qsTr("Requesting disconnect…") : qsTr("Requesting connection…"), checking_vpn:qsTr("Checking VPNs"), enabling_guard:qsTr("Enabling protection"), refreshing_source:qsTr("Updating Outline configuration"), resolving_endpoint:qsTr("Resolving server"), starting_core:qsTr("Starting Xray"), configuring_network:qsTr("Configuring network"), checking_connection:qsTr("Checking connection"), restoring_network:qsTr("Restoring network"), connected:qsTr("Connected"), paused_external:qsTr("Paused: another VPN"), disconnected:qsTr("Disconnected"), starting_openvpn:qsTr("Starting OpenVPN"), connecting_server:qsTr("Connecting to server"), verifying_certificate:qsTr("Verifying certificate"), receiving_config:qsTr("Receiving configuration"), applying_routes:qsTr("Applying work routes"), route_conflict:qsTr("Choose routes"), dns_conflict:qsTr("Choose DNS routes"), creating_interface:qsTr("Creating interface"), exchanging_keys:qsTr("Exchanging keys"), partial:qsTr("Partially connected")}
        return names[stage] || qsTr("Connecting…")
    }
    function failureName(failure) {
        i18n.language
        var names = {dns_timeout:qsTr("DNS is not responding"), dns_no_answer:qsTr("No IPv4 address"), dns_not_found:qsTr("Name not found"), dns_tls:qsTr("DNS TLS error"), dns_transport:qsTr("DNS unavailable"), dns_invalid_response:qsTr("Invalid DNS response"), vpn_dns_failed:qsTr("VPN DNS unavailable"), vpn_https_timeout:qsTr("HTTPS is not responding"), vpn_https_tls:qsTr("HTTPS certificate error"), vpn_https_response:qsTr("Invalid HTTPS response"), vpn_https_failed:qsTr("HTTPS through VPN failed")}
        if (failure.code === "openvpn_failed") {
            var message = String(failure.message || "").toLowerCase()
            if (message.indexOf("certificate") >= 0 || message.indexOf("tls") >= 0) return qsTr("Certificate error")
            if (message.indexOf("dns") >= 0) return qsTr("DNS unavailable")
            if (message.indexOf("timed out") >= 0) return qsTr("Connection timed out")
            if (message.indexOf("authentication") >= 0) return qsTr("Unsupported sign-in")
            if (message.indexOf("not installed") >= 0 || message.indexOf("is required") >= 0) return qsTr("OpenVPN is required")
            if (message.indexOf("route") >= 0 || message.indexOf("firewall") >= 0 || message.indexOf("protection") >= 0) return qsTr("Network setup failed")
            return qsTr("OpenVPN stopped")
        }
        if (failure.code === "wireguard_failed" || failure.code === "amneziawg_failed") {
            var detail = String(failure.message || "").toLowerCase()
            if (detail.indexOf("handshake") >= 0) return qsTr("No handshake response")
            if (detail.indexOf("dns") >= 0 || detail.indexOf("resolve") >= 0) return qsTr("DNS unavailable")
            if (detail.indexOf("route") >= 0 || detail.indexOf("firewall") >= 0 || detail.indexOf("protection") >= 0) return qsTr("Network setup failed")
            return qsTr("VPN tunnel stopped")
        }
        return names[failure.code] || qsTr("Connection failed")
    }
    function isWork(profile) { return ["openvpn", "wireguard", "amneziawg"].indexOf(profile.kind) >= 0 || /^(ovpn|wg|awg)-/.test(String(profile.id || "")) }
    function isWireGuard(profile) { return profile.kind === "wireguard" || profile.kind === "amneziawg" || /^(wg|awg)-/.test(String(profile.id || "")) }
    function protocolName(profile) { return ({vless:"VLESS", trojan:"Trojan", shadowsocks:"Shadowsocks", openvpn:"OpenVPN", wireguard:"WireGuard", amneziawg:"AmneziaWG"}[profile.kind] || (isWork(profile) ? "OpenVPN" : "VLESS")) + (profile.sourceKind === "outline" || (profile.source && profile.source.kind === "outline") ? " · Outline" : "") }
    function profileTabCount() { return isWireGuard(selectedProfile) ? 4 : isWork(selectedProfile) ? 3 : 2 }
    function peerState(value) { i18n.language; return {connected:qsTr("Connected"), connecting:qsTr("Waiting for handshake"), waiting_handshake:qsTr("Waiting for handshake"), reconnecting:qsTr("Reconnecting…"), error:qsTr("Peer unavailable"), disconnected:qsTr("Disconnected")}[value] || value }
    function liveProfile(profile) { return ((isWork(profile) ? snap.workProfiles : snap.profiles) || []).filter(function(p) { return p.id === profile.id })[0] || profile }
    function profileRuntime(profile) { return isWork(profile) ? (liveProfile(profile).runtime || ({})) : (profile.id === activeId || (!activeId && !operation.previousProfileId && operation.profileId === profile.id) ? runtime : {state:"disconnected"}) }
    function profileOperation(profile) { return isWork(profile) ? (backend.workRequests[profile.id] || liveProfile(profile).operation || ({})) : operation.profileId === profile.id ? operation : ({}) }
    function profileFailure(profile) { return isWork(profile) ? (liveProfile(profile).lastFailure || ({})) : (profileOperation(profile).failure || (snap.lastFailure && snap.lastFailure.profileId === profile.id ? snap.lastFailure : ({}))) }
    function failedSwitch(profile) { return liveProfile(profile).switchFailure || ({}) }
    function profileActive(profile) {
        var op = profileOperation(profile), state = profileRuntime(profile).state || "disconnected"
        return (op.action && !switchFinished(op) && op.stage !== "disconnected" && op.stage !== "request_failed") || state !== "disconnected"
    }
    function canActivate(profile) {
        if (!backend.online || snap.busyByOtherUser) return false
        var op = profileOperation(profile)
        if (isWork(profile)) return !(op.action === "disconnect" && op.stage !== "disconnected" && op.stage !== "cleanup_failed" && op.stage !== "request_failed")
        if (switching && profile.id !== operation.profileId && profile.id !== activeId) return false
        return (!cleaning || (profileActive(profile) && operation.stage === "cleanup_failed")) && (profileActive(profile) || !backend.networkBusy)
    }
    function statusText(profile) {
        i18n.language
        tick
        if (!backend.online) return qsTr("Service unavailable")
        if (snap.busyByOtherUser) return qsTr("In use by another user")
        if (backend.connectionErrorProfile === profile.id && backend.connectionError.length) return qsTr("Request failed")
        var op = profileOperation(profile)
        if (op.error) return qsTr("Request failed")
        if (op.stage === "switch_failed" && profile.id !== activeId) return qsTr("Switch failed")
        if (op.stage === "switch_cancelled" && profile.id !== activeId) return qsTr("Switch cancelled")
        if (!profileActive(profile) && failedSwitch(profile).message) return qsTr("Switch failed")
        var failure = profileFailure(profile)
        if (!profileActive(profile) && failedSwitch(profile).message) failure = failedSwitch(profile)
        if (op.stage === "route_conflict" || op.stage === "dns_conflict") return qsTr("Choose routes")
        if (op.stage === "cleanup_failed") return qsTr("Disconnect failed\nRetry cleanup")
        if (op.stage === "retry_wait") return qsTr("%1\nRetry in %2 s").arg(failureName(failure)).arg(Math.max(0, Math.ceil((Number(op.nextRetryAt) - Date.now()) / 1000)))
        if (op.stage && !switchFinished(op) && op.stage !== "disconnected" && op.stage !== "connected" && op.stage !== "partial" && op.stage !== "paused_external") {
            var elapsed = op.stageStartedAt ? Math.max(0, Math.floor((Date.now() - Number(op.stageStartedAt)) / 1000)) : 0
            return elapsed > 0 ? qsTr("%1 · %2 s").arg(stageName(op.stage, op.action)).arg(elapsed) : stageName(op.stage, op.action)
        }
        if (!isWork(profile) && profile.id !== activeId && (!op.action || switchFinished(op))) return qsTr("Disconnected")
        var names = {connected:qsTr("Connected"), partial:qsTr("Partially connected"), connecting:qsTr("Connecting…"), reconnecting:qsTr("Reconnecting…"), paused_external:qsTr("Another VPN is active"), error:qsTr("Connection failed"), conflict:qsTr("Choose routes"), disconnected:qsTr("Disconnected")}
        return names[profileRuntime(profile).state] || qsTr("Disconnected")
    }
    function statusDetail(profile) {
        i18n.language
        if (!backend.online) return qsTr("Service unavailable — VPN state is unknown. Click to open the last diagnostic snapshot.")
        if (snap.busyByOtherUser) return qsTr("In use by another user")
        if (backend.connectionErrorProfile === profile.id && backend.connectionError.length) return appWindow.localizedMessage(backend.connectionError)
        var op = profileOperation(profile)
        if (op.error) return appWindow.localizedMessage(op.error)
        var text = statusText(profile)
        var failure = profileFailure(profile)
        if (!profileActive(profile) && failedSwitch(profile).message) failure = failedSwitch(profile)
        var current = profileRuntime(profile)
        if (current.message) text += "\n" + appWindow.localizedMessage(current.message)
        if (op.stage === "cleanup_failed") return qsTr("Could not fully restore the network. Click Retry to disconnect again.\n%1").arg(appWindow.localizedMessage(current.message || ""))
        if (op.attempt) text += "\n" + qsTr("Attempt %1").arg(op.attempt)
        if ((op.stage === "retry_wait" || switchFinished(op) || !profileActive(profile)) && failure.message) text += "\n" + appWindow.localizedMessage(failure.message)
        return text + "\n" + qsTr("Click to open profile diagnostics.")
    }
    function connectionLabel(profile) {
        i18n.language
        var op = profileOperation(profile)
        if (op.stage === "switch_failed" && profile.id !== activeId) return qsTr("Retry")
        if (!profileActive(profile) && failedSwitch(profile).message) return qsTr("Retry")
        if (op.stage === "cleanup_failed") return qsTr("Retry")
        if (op.action === "disconnect" && op.stage !== "disconnected") return qsTr("Disconnecting…")
        if (!profileActive(profile)) return qsTr("Connect")
        if (op.stage && !switchFinished(op) && op.stage !== "connected" && op.stage !== "partial" && op.stage !== "paused_external" && op.stage !== "retry_wait") return qsTr("Cancel")
        var current = profileRuntime(profile)
        return current.state === "connecting" || current.state === "reconnecting" ? qsTr("Cancel") : qsTr("Disconnect")
    }
    function openDiagnostics(profile) {
        if (!profile) profile = profiles.filter(function(p) { return p.id === activeId })[0] || ({})
        diagnosticProfile = profile
        diagnosticsDialog.open(); backend.getDiagnostics(profile.id || "")
    }
    function showProfile(profile) {
        selectedProfile = profile; renameField.text = profile.name; profileIconId = profile.iconId || "antenna"
        debugLogging.checked = !!profile.debugLogging; profileTabs.currentIndex = 0
        if (isWork(profile)) backend.refreshWorkRoutes()
        logHistoryMode = false; backend.loadProfileLogs(profile.id, true); detailDialog.open()
    }
    function chooseIcon(target, id, iconId) { iconTarget = target; iconTargetId = id; iconPicker.selectedIcon = iconId || "antenna"; iconPicker.open() }
    function activateProfile(profile) {
        if (isWork(profile)) {
            if (profileActive(profile)) backend.disconnectWorkProfile(profile.id)
            else backend.connectWorkProfile(profile.id)
        } else if (switching && profile.id === operation.profileId) backend.cancelProfileSwitch(operation.id || "")
        else if (profileActive(profile)) backend.disconnectProfile()
        else backend.connectProfile(profile.id)
    }
    function openSettings() { bootProfile.beginEdit(); settingsDialog.open() }
    function openRoutes() { routesDialog.open(); backend.refreshWorkRoutes() }
    function routeTargetName(target) {
        if (target === "local") return qsTr("Local network / Docker")
        var profile = (snap.workProfiles || []).filter(function(p) { return p.id === target })[0]
        return profile ? profile.name : target
    }
    function routeSource(source) {
        i18n.language
        var values = {manual:qsTr("Manual rule"), server:qsTr("VPN configuration"), openvpn:qsTr("OpenVPN server"), wireguard:"WireGuard · AllowedIPs", amneziawg:"AmneziaWG · AllowedIPs", local:qsTr("Local network / Docker"), external:qsTr("External VPN"), dns:"DNS"}
        return values[source] || qsTr("Automatic route")
    }
    function routeState(state) {
        i18n.language
        var values = {active:qsTr("Active"), protected:qsTr("Blocked until VPN recovers"), overridden:qsTr("Another route selected"), blocked:qsTr("Blocked until VPN recovers"), conflict:qsTr("Choose a route"), inactive:qsTr("Inactive"), available:qsTr("Available"), pending:qsTr("Waiting for VPN"), selected:qsTr("Selected")}
        return values[state] || state || ""
    }
    function openImport() { backend.cancelImport(); importDialog.sourceKind = "text"; importArea.text = ""; importDialog.previewReady = false; importDialog.iconChoices = ({}); importDialog.open() }
    function openSubscriptionImport() {
        backend.cancelImport(); importDialog.sourceKind = "subscription"; importDialog.previewReady = false; importDialog.iconChoices = ({})
        importDialog.open(); backend.prepareImport(subscriptionUrl.text.trim(), "subscription", subscriptionName.text)
    }
    function formattedDate(value) { i18n.language; if (!value) return qsTr("not updated yet"); return typeof value === "number" ? displayDateTime(value * 1000) : value }
    function displayDateTime(value) { return new Date(value).toLocaleString(Qt.locale(i18n.localeName), Locale.ShortFormat) }
    function logLevel(value) { i18n.language; var levels = { debug: qsTr("DEBUG"), info: qsTr("INFO"), warning: qsTr("WARNING"), error: qsTr("ERROR") }; return levels[value] || String(value).toUpperCase() }
    function splitLines(value) { return value.split(/[\n,]/).map(function(v) { return v.trim() }).filter(function(v) { return v.length > 0 }) }
    Component.onCompleted: demoTimer.start()
    Timer { id: demoTimer; interval: 80; onTriggered: {
        if (demoScreen === "import") openImport()
        else if (demoScreen === "wireguard") backend.setDemoState("wireguard-vpns")
        else if (demoScreen === "peers") { backend.setDemoState("wireguard-vpns"); appWindow.showProfile(appWindow.profiles[2]); profileTabs.currentIndex = 3 }
        else if (demoScreen === "routes") { backend.setDemoState("work-vpns"); openRoutes() }
        else if (demoScreen === "work-profile") { backend.setDemoState("work-vpns"); appWindow.showProfile(appWindow.profiles[1]); profileTabs.currentIndex = 2 }
        else if (demoScreen === "work-import") {
            openImport(); importDialog.sourceKind = "work"
            backend.prepareWorkImport([{name:qsTr("Office West"), content:"client\ndev tun\nremote west.example.net 1194 udp\n"},
                {name:qsTr("Office East"), content:"[Interface]\nAddress = 10.72.0.2/32\n[Peer]\nEndpoint = east.example.net:51820\nAllowedIPs = 10.72.0.0/16\n"},
                {name:qsTr("Backup"), content:"[Interface]\nAddress = 10.73.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\n[Peer]\nEndpoint = backup.example.net:443\nAllowedIPs = 10.73.0.0/16\n"}])
        }
        else if (demoScreen === "settings" || demoScreen === "subscriptions" || demoScreen === "vpn" || demoScreen === "vpn-actions") { settingsTabs.currentIndex = demoScreen === "settings" ? 0 : (demoScreen === "subscriptions" ? 1 : 2); openSettings(); if (demoScreen === "vpn-actions") vpnPreviewTimer.start() }
        else if (demoScreen === "diagnostics") openDiagnostics()
        else if ((demoScreen === "profile" || demoScreen === "logs" || demoScreen === "icons") && appWindow.profiles.length) { appWindow.showProfile(appWindow.profiles[0]); if (demoScreen === "logs") profileTabs.currentIndex = 1; if (demoScreen === "icons") appWindow.chooseIcon("profile", "", appWindow.profileIconId) }
        else if (demoScreen === "combo") { openSettings(); comboPreviewTimer.start() }
        else if (demoScreen === "outline") { backend.setDemoState("proxy"); appWindow.showProfile(appWindow.profiles[2]) }
        else if (demoScreen === "import-preview") { openImport(); importArea.text = "vless://00000000-0000-4000-8000-000000000011@example.net:443?security=tls#" + qsTr("Primary") + "\ntrojan://synthetic-password@backup.example.net:443?security=tls#" + qsTr("Backup") + "\nss://aes-256-gcm:synthetic-password@work.example.net:443#" + qsTr("Work"); importDialog.previewInput = importArea.text; backend.prepareImport(importArea.text, importMode.currentIndex === 1 ? "outline" : "text", "") }
        else if (demoScreen === "error") errorDialog.open()
    } }

    Timer { id: vpnPreviewTimer; interval: 80; onTriggered: { vpnAdvanced.checked = true; Qt.callLater(function() { vpnScroll.contentItem.contentY = Math.max(0, vpnScroll.contentHeight - vpnScroll.availableHeight) }) } }
    Timer { id: comboPreviewTimer; interval: 80; onTriggered: bootProfile.popup.open() }
    FontLoader { id: condensedFont; source: "qrc:/assets/fonts/RobotoCondensed-Regular.ttf" }
    FontLoader { id: monoLoader; source: "qrc:/assets/fonts/IosevkaTerm-Medium.ttf" }
    Timer { interval: 1000; running: appWindow.visible; repeat: true; onTriggered: appWindow.tick++ }
    Shortcut { sequence: "Ctrl+I"; onActivated: openImport() }
    Shortcut { sequence: "Ctrl+,"; onActivated: openSettings() }
    Shortcut { sequence: "Ctrl+D"; onActivated: openDiagnostics() }
    Shortcut { sequence: "Ctrl+Q"; onActivated: backend.quitInterface() }
    Shortcut { sequence: "F5"; onActivated: backend.refresh() }
    onClosing: function(close) { if (backend.trayAvailable) { close.accepted = false; hide() } }
    Connections {
        target: backend
        function onProfileLogsAboutToChange() { appWindow.logFollowEnd = logList.atYEnd; appWindow.logSavedPosition = logList.contentY }
        function onSnapshotChanged() { if (!bootProfile.dirty) bootProfile.beginEdit() }
        function onProfileLogsChanged() { Qt.callLater(function() { if (!appWindow.logHistoryMode && appWindow.logFollowEnd) logList.positionViewAtEnd(); else if (!appWindow.logHistoryMode) logList.contentY = appWindow.logSavedPosition }) }
        function onRaiseRequested() { appWindow.showNormal(); appWindow.requestActivate() }
        function onWorkFilesRead() { importDialog.sourceKind = "work"; importDialog.previewReady = false }
        function onImportFileRead(text) { importArea.text = text; importDialog.previewReady = false }
        function onPreviewChanged() {
            importDialog.previewReady = !!backend.preview.draftId && (importDialog.sourceKind !== "text" || importArea.text === importDialog.previewInput)
            if (importDialog.previewReady) {
                var choices = ({})
                ;(backend.preview.profiles || []).forEach(function(profile) { choices[profile.id] = profile.iconId || "antenna" })
                importDialog.iconChoices = choices
            }
        }
        function onErrorChanged() { if (backend.error.length) errorDialog.open() }
        function onOperationDone(operation, result) {
            if (result.error) return
            if (operation === "ImportProfiles" || operation === "CommitImport" || operation === "CommitWorkImport") { importDialog.close(); importArea.text = ""; if (importDialog.sourceKind === "subscription") { subscriptionUrl.text = ""; subscriptionName.text = "" } }
            if (operation === "UpdateProfile" || operation === "RemoveProfile" || operation === "UpdateWorkProfile" || operation === "RemoveWorkProfile") detailDialog.close()
            if (operation === "RefreshSubscriptions") {
                var failed = (result.results || []).filter(function(r) { return !r.updated })
                appWindow.subscriptionFailureCount = failed.length; appWindow.subscriptionRefreshDone = true
            }
            if (operation === "SetBootProfile") bootProfile.beginEdit()
            if (operation === "SetVPNBinding") appWindow.vpnBindingSaved = true
        }
    }

    Item {
        id: scene
        width: 944; height: 960
        scale: initialScale
        transformOrigin: Item.TopLeft
        Image { anchors.fill: parent; source: "qrc:/assets/skin/window.png"; fillMode: Image.Stretch; smooth: true }
        MouseArea { x: 20; y: 0; width: 744; height: 79; onPressed: appWindow.startSystemMove(); acceptedButtons: Qt.LeftButton }
        Button { PointerHover {}
            x: 783; y: 10; width: 70; height: 63
            background: Rectangle { color: parent.hovered ? "#20ffe3a0" : "transparent"; radius: 4; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
            Accessible.name: qsTr("Minimize")
            ToolTip.visible: hovered; ToolTip.text: qsTr("Minimize")
            onClicked: appWindow.showMinimized()
        }
        Button { PointerHover {}
            x: 861; y: 10; width: 66; height: 63
            objectName: "close-button"
            background: Rectangle { color: parent.hovered ? "#35ffb083" : "transparent"; radius: 4; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
            Accessible.name: qsTr("Close interface")
            ToolTip.visible: hovered; ToolTip.text: backend.trayAvailable ? qsTr("Hide to tray; VPN will stay connected") : qsTr("Close window; VPN will stay connected")
            onClicked: appWindow.close()
        }
        Button { PointerHover {}
            x: 54; y: 94; width: 232; height: 69
            id: importButton
            objectName: "import-button"
            padding: 0
            contentItem: Item { Text { objectName: "import-label"; textFormat: Text.PlainText; x: 89; y: 0; width: 133; height: parent.height; text: qsTr("Import", "toolbar label"); color: "#e7c68a"; font.family: appWindow.bodyFont; font.pixelSize: 36; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter } }
            background: Rectangle { color: parent.hovered ? "#20ffe3a0" : "transparent"; radius: 4; border.color: parent.visualFocus ? "#a7ef9c" : "transparent" }
            Accessible.name: qsTr("Import profiles", "toolbar action")
            TerminalToolTip { control: importButton; text: qsTr("Import profiles", "toolbar action") }
            onClicked: openImport()
        }
        Button { PointerHover {}
            x: 802; y: 94; width: 95; height: 69
            objectName: "settings-button"
            background: Rectangle { color: parent.hovered ? "#20ffe3a0" : "transparent"; radius: 4; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
            Accessible.name: qsTr("Settings")
            ToolTip.visible: hovered; ToolTip.text: qsTr("Settings")
            onClicked: openSettings()
        }

        Rectangle { x: 40; y: appWindow.profiles.length === 1 ? 367 : 557; width: 872; height: appWindow.profiles.length === 1 ? 380 : 190; visible: appWindow.profiles.length === 1 || appWindow.profiles.length === 2; color: "#141913"; border.color: "#554c38"; radius: 8 }
        ListView {
            id: profileList
            objectName: "profile-list"
            x: 40; y: 182; width: 872; height: 565
            clip: true
            spacing: 0
            boundsBehavior: Flickable.StopAtBounds
            model: appWindow.profiles
            ScrollBar.vertical: ScrollBar { policy: profileList.count > 3 ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff; width: 10 }
            delegate: Item {
                id: row
                required property var modelData
                required property int index
                width: 872; height: index % 3 === 0 ? 185 : 190
                property int variant: index % 3
                property int cardHeight: [182, 186, 190][variant]
                property bool active: appWindow.profileActive(modelData)
                property bool lit: active && appWindow.profileRuntime(modelData).state === "connected"
                Image { width: parent.width; height: row.cardHeight; source: "qrc:/assets/skin/card-" + (row.variant + 1) + ".png" }
                Image { x: 221; y: row.variant === 0 ? 88 : 93; width: 54; height: 53; source: "qrc:/assets/skin/led-" + (row.lit ? "on" : "off") + ".png" }
                Text { textFormat: Text.PlainText;
                    x: 223; y: [41,42,41][row.variant]; width: 302; height: 43
                    text: row.modelData.name || qsTr("Profile")
                    color: "#78df8a"
                    font.family: appWindow.monoFont; font.pixelSize: 40; font.letterSpacing: 0.6
                    elide: Text.ElideRight
                    verticalAlignment: Text.AlignVCenter
                }
                Text { objectName: "profile-kind-" + row.index; x: 224; y: [20,21,20][row.variant]; width: 302; height: 20; text: appWindow.protocolName(row.modelData); textFormat: Text.PlainText; color: "#90a68a"; font.family: appWindow.bodyFont; font.pixelSize: 18 }
                Button { PointerHover {}
                    id: profileStatus
                    objectName: "status-" + row.index
                    x: 283; y: row.variant === 0 ? 86 : 93; width: 250; height: 64
                    padding: 0; hoverEnabled: true
                    text: appWindow.statusText(row.modelData)
                    Accessible.name: appWindow.statusDetail(row.modelData)
                    background: Rectangle { color: "transparent"; border.color: profileStatus.visualFocus ? "#a0e8a4" : "transparent"; radius: 3 }
                    contentItem: Text {
                        textFormat: Text.PlainText; text: profileStatus.text
                        color: row.lit ? "#78df8a" : (row.active ? "#d6b468" : "#708985")
                        font.family: appWindow.monoFont; font.pixelSize: text.length > 18 ? 22 : 30; font.letterSpacing: 0.1
                        wrapMode: Text.Wrap
                        elide: Text.ElideRight; verticalAlignment: Text.AlignVCenter
                        maximumLineCount: 2
                    }
                    TerminalToolTip { control: profileStatus; text: appWindow.statusDetail(row.modelData) }
                    onClicked: appWindow.openDiagnostics(row.modelData)
                }
                Button { PointerHover {}
                    id: connectionButton
                    objectName: "connect-" + row.index
                    x: 588; y: row.variant === 0 ? 43 : 48; width: 247; height: row.variant === 0 ? 88 : 89
                    enabled: appWindow.canActivate(row.modelData)
                    hoverEnabled: true
                    padding: 0
                    Accessible.name: qsTr("%1 %2").arg(appWindow.connectionLabel(row.modelData)).arg(row.modelData.name)
                    text: appWindow.connectionLabel(row.modelData)
                    background: Item {
                        Image { anchors.fill: parent; source: "qrc:/assets/skin/button-" + (row.active ? "red" : "green") + ".png" }
                        Rectangle { anchors.fill: parent; anchors.margins: 5; radius: 9; color: connectionButton.down ? "#33000000" : (connectionButton.hovered ? "#14ffeead" : "transparent"); border.color: connectionButton.visualFocus ? "#d3eab0" : "transparent"; border.width: 2 }
                    }
                    contentItem: Text { textFormat: Text.PlainText;
                        text: connectionButton.text
                        color: connectionButton.enabled ? "#e7c68a" : "#aa9570"
                        font.family: appWindow.monoFont; font.pixelSize: text.length > 10 ? 30 : 38; font.letterSpacing: 0.1
                        horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: appWindow.activateProfile(row.modelData)
                }
                ProfileIcon {
                    x: 44; y: [31,35,36][row.variant]; width: row.variant === 0 ? 114 : 115; height: [115,114,116][row.variant]
                    iconId: row.modelData.iconId || ["antenna","dish","globe"][row.variant]
                    visible: iconId !== ["antenna","dish","globe"][row.variant]
                }
                Button { PointerHover {}
                    objectName: "profile-" + row.index
                    x: 28; y: 25; width: 134; height: 135
                    background: Rectangle { color: parent.hovered ? "#1cffe1a0" : "transparent"; border.color: parent.visualFocus ? "#8be599" : "transparent"; radius: 8 }
                    Accessible.name: qsTr("Profile details: %1").arg(row.modelData.name)
                    ToolTip.visible: hovered; ToolTip.text: qsTr("Name, emblem and connection logs")
                    onClicked: appWindow.showProfile(row.modelData)
                }
                TapHandler { acceptedButtons: Qt.RightButton; onTapped: appWindow.showProfile(row.modelData) }
            }
        }
        Rectangle {
            x: 56; y: 196; width: 834; height: 523
            visible: appWindow.profiles.length === 0
            color: "#07130b"; radius: 12; border.color: "#796e4f"
            Column {
                anchors.centerIn: parent; spacing: 24
                Text { textFormat: Text.PlainText; width: 690; text: backend.online ? qsTr("No profiles") : qsTr("System service unavailable"); color: "#8ceaa0"; font.family: appWindow.bodyFont; font.pixelSize: 38; horizontalAlignment: Text.AlignHCenter }
                Text { textFormat: Text.PlainText; width: 690; text: backend.online ? qsTr("Import VPN links\nor add a subscription in settings.") : qsTr("Install and start vault443d,\nthen refresh the status."); color: "#829a89"; font.family: appWindow.bodyFont; font.pixelSize: 26; horizontalAlignment: Text.AlignHCenter }
                MetalButton { objectName: "empty-action"; anchors.horizontalCenter: parent.horizontalCenter; text: backend.online ? qsTr("Import") : qsTr("Refresh"); onClicked: backend.online ? openImport() : backend.refresh() }
            }
        }
        Item {
            x: 56; y: 760; width: 830; height: 74
            objectName: "traffic-panel"
            Image { anchors.fill: parent; source: "qrc:/assets/skin/stats.png" }
            Rectangle { x: 180; y: 17; width: 2; height: 40; color: "#365c3c" }
            Rectangle { x: 534; y: 17; width: 2; height: 40; color: "#365c3c" }
            TrafficValue {
                objectName: "session-duration"; x: 14; y: 7; width: 156; height: 60
                text: appWindow.sessionDuration(); font.family: appWindow.monoFont; font.pixelSize: 28
                description: qsTr("Session duration: %1").arg(appWindow.sessionDuration())
                explanation: qsTr("Session duration includes automatic retries and pauses. Manual disconnection freezes the last session.") + "\n" + appWindow.trafficExplanation()
            }
            TrafficValue {
                objectName: "download-rate"; x: 196; y: 7; width: 154; height: 60
                text: "↓ " + appWindow.trafficText(appWindow.traffic.downloadBytesPerSecond, true)
                font.family: appWindow.monoFont
                description: qsTr("Download speed") + ": " + appWindow.fullTraffic(appWindow.traffic.downloadBytesPerSecond, true)
                explanation: qsTr("Measured every second. Speed is zero while paused or waiting to retry.") + "\n" + appWindow.trafficExplanation()
            }
            TrafficValue {
                objectName: "upload-rate"; x: 362; y: 7; width: 154; height: 60
                text: "↑ " + appWindow.trafficText(appWindow.traffic.uploadBytesPerSecond, true)
                font.family: appWindow.monoFont
                description: qsTr("Upload speed") + ": " + appWindow.fullTraffic(appWindow.traffic.uploadBytesPerSecond, true)
                explanation: qsTr("Measured every second. Speed is zero while paused or waiting to retry.") + "\n" + appWindow.trafficExplanation()
            }
            TrafficValue {
                objectName: "download-total"; x: 550; y: 7; width: 125; height: 60
                text: "↓ " + appWindow.trafficText(appWindow.traffic.downloadBytes, false)
                font.family: appWindow.monoFont
                description: qsTr("Downloaded this session") + ": " + appWindow.fullTraffic(appWindow.traffic.downloadBytes, false)
                explanation: qsTr("Reopening the interface does not reset session totals.") + "\n" + appWindow.trafficExplanation()
            }
            TrafficValue {
                objectName: "upload-total"; x: 687; y: 7; width: 125; height: 60
                text: "↑ " + appWindow.trafficText(appWindow.traffic.uploadBytes, false)
                font.family: appWindow.monoFont
                description: qsTr("Uploaded this session") + ": " + appWindow.fullTraffic(appWindow.traffic.uploadBytes, false)
                explanation: qsTr("Reopening the interface does not reset session totals.") + "\n" + appWindow.trafficExplanation()
            }
        }

        Button { PointerHover {}
            x: 81; y: 868; width: 342; height: 68
            objectName: "autostart-button"
            background: Rectangle { color: parent.hovered ? "#17ffdc9b" : "transparent"; radius: 7; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
            Accessible.name: qsTr("Open interface at login")
            Accessible.checkable: true; Accessible.checked: backend.autostart
            Image { x: 19; y: 8; width: 52; height: 50; source: "qrc:/assets/skin/checkbox-" + (backend.autostart ? "on" : "off") + ".png" }
            Text { textFormat: Text.PlainText; objectName: "autostart-label"; x: 91; y: 8; width: 231; height: 49; text: qsTr("Launch at login"); color: "#e7c68a"; font.family: appWindow.bodyFont; font.pixelSize: 26; verticalAlignment: Text.AlignVCenter }
            onClicked: backend.setAutostart(!backend.autostart)
        }
        Button { PointerHover {}
            x: 523; y: 868; width: 345; height: 68
            objectName: "boot-button"
            background: Rectangle { color: parent.hovered ? "#17ffdc9b" : "transparent"; radius: 7; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
            Accessible.name: qsTr("VPN at system boot")
            Accessible.checkable: true; Accessible.checked: (appWindow.snap.bootProfileId || "").length > 0
            Image { x: 19; y: 8; width: 52; height: 50; source: "qrc:/assets/skin/checkbox-" + ((appWindow.snap.bootProfileId || "").length ? "on" : "off") + ".png" }
            Text { textFormat: Text.PlainText; objectName: "boot-label"; x: 91; y: 8; width: 234; height: 49; text: qsTr("VPN at system boot"); color: "#e7c68a"; font.family: appWindow.bodyFont; font.pixelSize: 26; verticalAlignment: Text.AlignVCenter }
            onClicked: {
                if ((appWindow.snap.bootProfileId || "").length && appWindow.snap.canAdmin) backend.setBootProfile("")
                else openSettings()
            }
        }
        Rectangle {
            x: 320; y: 101; width: 452; height: 53; radius: 4
            visible: !backend.online || appWindow.snap.busyByOtherUser || appWindow.runtime.state === "paused_external" || appWindow.runtime.state === "error"
            color: "#df121710"; border.color: "#8f7854"
            Text { textFormat: Text.PlainText; anchors.fill: parent; anchors.margins: 7; text: !backend.online ? qsTr("Service unavailable") : (appWindow.snap.busyByOtherUser ? qsTr("Another user’s VPN") : (appWindow.runtime.state === "paused_external" ? qsTr("Paused: another VPN") : qsTr("Error · open diagnostics"))); color: "#d9bc78"; font.family: appWindow.bodyFont; font.pixelSize: 24; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
            PointerHover {}
            MouseArea { anchors.fill: parent; onClicked: { if (appWindow.snap.busyByOtherUser) takeoverDialog.open(); else appWindow.openDiagnostics() } }
        }
    }

    FileDialog { id: importFile; title: qsTr("Import profiles"); nameFilters: [qsTr("VPN and text files (*.txt *.conf *.ovpn *.vpn)"), qsTr("All files (*)")]; onAccepted: {
        if (String(selectedFile).toLowerCase().endsWith(".ovpn")) backend.readWorkFiles([selectedFile])
        else backend.readImportFile(selectedFile)
    } }
    FileDialog { id: workVPNFiles; title: qsTr("Import VPN configurations"); fileMode: FileDialog.OpenFiles; nameFilters: [qsTr("VPN configurations (*.ovpn *.conf *.vpn)"), qsTr("All files (*)")]; onAccepted: backend.readWorkFiles(selectedFiles) }
    TerminalDialog {
        id: importDialog
        objectName: "import-dialog"
        title: sourceKind === "subscription" ? qsTr("Import subscription") : sourceKind === "work" ? qsTr("Import VPN configurations") : qsTr("Import profiles")
        property bool previewReady: false
        property string previewInput: ""
        property string sourceKind: "text"
        property var iconChoices: ({})
        onClosed: { backend.cancelImport(); previewReady = false }
        ColumnLayout {
            anchors.fill: parent; spacing: 13
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: importDialog.sourceKind === "subscription" ? qsTr("Review subscription profiles and choose their emblems. The subscription is saved after confirmation.") : importDialog.sourceKind === "work" ? qsTr("Review the VPN profiles and choose their emblems. Certificates and keys stay private.") : qsTr("Paste VLESS, Trojan, Shadowsocks or ssconf:// links, a WireGuard configuration or Amnezia vpn:// keys."); color: "#c3b38e"; wrapMode: Text.Wrap; font.pixelSize: 21 }
            TerminalCombo {
                id: importMode; objectName: "import-mode"; visible: importDialog.sourceKind === "text"
                Layout.fillWidth: true; model: [qsTr("Links / VPN configuration"), qsTr("Outline · HTTPS / ssconf://")]
                enabled: !backend.importPreparing && !backend.importCommitting
                onActivated: {importDialog.previewReady = false; backend.cancelImport()}
            }
            ScrollView {
                visible: importDialog.sourceKind === "text"
                Layout.fillWidth: true; Layout.preferredHeight: 175
                TextArea {
                    id: importArea; wrapMode: TextEdit.WrapAnywhere; color: "#88d995"; font.family: appWindow.monoFont; font.pixelSize: 18
                    objectName: "import-text"
                    placeholderText: "vless://…  trojan://…  ss://…  ssconf://…"; placeholderTextColor: "#667969"; selectByMouse: true
                    background: Rectangle { color: "#09120c"; border.color: "#6d6046"; radius: 5 }
                    enabled: !backend.importCommitting
                    onTextChanged: { importDialog.previewReady = false; backend.cancelImport() }
                }
            }
            RowLayout {
                visible: importDialog.sourceKind !== "subscription"
                MetalButton { visible: importDialog.sourceKind === "text"; text: qsTr("From file"); small: true; enabled: !backend.importPreparing && !backend.importCommitting; onClicked: importFile.open() }
                MetalButton { objectName: "import-work"; text: qsTr("VPN files"); small: true; implicitWidth: 220; enabled: !backend.importPreparing && !backend.importCommitting; onClicked: workVPNFiles.open() }
                Item { Layout.fillWidth: true }
                MetalButton { visible: importDialog.sourceKind === "text"; objectName: "import-preview"; text: qsTr("Review"); small: true; enabled: importArea.text.trim().length > 0 && !backend.importPreparing && !backend.importCommitting; onClicked: { importDialog.previewInput = importArea.text; backend.prepareImport(importArea.text, importMode.currentIndex === 1 ? "outline" : "text", "") } }
            }
            Text { textFormat: Text.PlainText; objectName: "import-preparing"; visible: backend.importPreparing; text: qsTr("Preparing profiles…"); color: "#a8b794"; font.pixelSize: 21 }
            ListView {
                objectName: "import-profiles"
                Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                model: importDialog.previewReady ? (backend.preview.profiles || []) : []
                delegate: Item {
                    required property var modelData
                    required property int index
                    id: importRow
                    width: ListView.view.width; height: 83
                    Button { PointerHover {}
                        objectName: "import-icon-" + parent.index
                        x: 2; y: 4; width: 70; height: 71; padding: 2
                        enabled: !parent.modelData.duplicate && !backend.importCommitting
                        contentItem: ProfileIcon { iconId: importDialog.iconChoices[importRow.modelData.id] || "antenna" }
                        background: Rectangle { color: parent.down ? "#33000000" : "transparent"; border.color: parent.visualFocus ? "#a0e8a4" : "transparent"; radius: 6 }
                        Accessible.name: qsTr("Choose an emblem for %1").arg(parent.modelData.name)
                        onClicked: appWindow.chooseIcon("import", parent.modelData.id, importDialog.iconChoices[parent.modelData.id])
                    }
                    Text { textFormat: Text.PlainText; x: 86; y: 8; width: parent.width - 98; height: 32; text: parent.modelData.duplicate ? qsTr("Already added: %1").arg(parent.modelData.name) : qsTr("✓ %1").arg(parent.modelData.name); color: parent.modelData.duplicate ? "#a69671" : "#8dd49a"; font.pixelSize: 22; elide: Text.ElideRight }
                    Text { textFormat: Text.PlainText; x: 86; y: 41; width: parent.width - 98; height: 29; text: appWindow.protocolName(parent.modelData) + " · " + (parent.modelData.server || ""); color: "#9b9e88"; font.pixelSize: 18; elide: Text.ElideRight }
                }
                ScrollBar.vertical: ScrollBar {}
            }
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; visible: importDialog.previewReady; text: { var errors = backend.preview.errors || []; return errors.map(function(e) { return (importDialog.sourceKind === "work" ? qsTr("File %1: %2") : qsTr("Entry %1: %2")).arg(e.line).arg(appWindow.localizedMessage(e.message)) }).join("\n") } color: "#e4a187"; wrapMode: Text.Wrap; font.pixelSize: 18; maximumLineCount: 3; elide: Text.ElideRight }
            RowLayout {
                MetalButton { objectName: "import-cancel"; text: qsTr("Cancel"); onClicked: importDialog.close() }
                Item { Layout.fillWidth: true }
                MetalButton { objectName: "import-commit"; text: qsTr("Import"); enabled: importDialog.previewReady && (backend.preview.profiles || []).length > 0 && !backend.importPreparing && !backend.importCommitting; onClicked: backend.commitImport(importDialog.iconChoices) }
            }
        }
    }

    IconPicker {
        id: iconPicker
        onChosen: function(iconId) {
            if (appWindow.iconTarget === "profile") appWindow.profileIconId = iconId
            else { var choices = Object.assign({}, importDialog.iconChoices); choices[appWindow.iconTargetId] = iconId; importDialog.iconChoices = choices }
        }
    }
    TerminalDialog {
        id: detailDialog; title: qsTr("Profile and connection"); height: 830
        ColumnLayout {
            anchors.fill: parent; spacing: 14
            TabBar {
                id: profileTabs; Layout.fillWidth: true; implicitWidth: 0
                TerminalTabButton { width: profileTabs.width / (appWindow.profileTabCount()); text: qsTr("Profile") }
                TerminalTabButton { objectName: "logs-tab"; width: profileTabs.width / (appWindow.profileTabCount()); text: qsTr("Logs") }
                TerminalTabButton { objectName: "profile-routes-tab"; visible: appWindow.isWork(appWindow.selectedProfile); enabled: visible; width: visible ? profileTabs.width / appWindow.profileTabCount() : 0; text: qsTr("Routes") }
                TerminalTabButton { objectName: "profile-peers-tab"; visible: appWindow.isWireGuard(appWindow.selectedProfile); enabled: visible; width: visible ? profileTabs.width / appWindow.profileTabCount() : 0; text: qsTr("Peers") }
            }
            StackLayout {
                currentIndex: profileTabs.currentIndex; Layout.fillWidth: true; Layout.fillHeight: true
                ColumnLayout {
                    spacing: 16
                    RowLayout {
                        Button { PointerHover {}
                            objectName: "profile-icon-choice"
                            Layout.preferredWidth: 114; Layout.preferredHeight: 115
                            padding: 0
                            contentItem: ProfileIcon { iconId: appWindow.profileIconId }
                            background: Rectangle { color: "transparent"; border.color: parent.visualFocus ? "#a0e8a4" : "transparent" }
                            Accessible.name: qsTr("Choose profile emblem")
                            onClicked: appWindow.chooseIcon("profile", "", appWindow.profileIconId)
                        }
                        TerminalField { id: renameField; objectName: "profile-name"; Layout.fillWidth: true; placeholderText: qsTr("Profile name"); maximumLength: 80 }
                    }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Server: %1\nTransport: %2\nSecurity: %3").arg(appWindow.selectedProfile.server || "").arg(appWindow.selectedProfile.transport || "").arg(appWindow.isWireGuard(appWindow.selectedProfile) ? appWindow.protocolName(appWindow.selectedProfile) : appWindow.isWork(appWindow.selectedProfile) ? "TLS" : appWindow.selectedProfile.security || ""); color: "#bcb294"; font.pixelSize: 23; lineHeight: 1.4; wrapMode: Text.WrapAnywhere }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Click the emblem to change it. To change connection details, import a new profile."); color: "#829485"; font.pixelSize: 20; wrapMode: Text.Wrap }
                    ColumnLayout {
                        visible: !!appWindow.liveProfile(appWindow.selectedProfile).source
                        Layout.fillWidth: true
                        property var source: appWindow.liveProfile(appWindow.selectedProfile).source || ({})
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Outline · updated %1").arg(parent.source.updatedAt ? appWindow.displayDateTime(Number(parent.source.updatedAt) * 1000) : "—"); color: "#bcb294"; font.pixelSize: 20; elide: Text.ElideRight }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: parent.source.blocked ? qsTr("Source denied access. Cached connection is blocked.") : parent.source.usingCached ? qsTr("Using the last verified configuration.") : qsTr("Verified configuration. Updates apply at the next connection."); color: parent.source.blocked || parent.source.usingCached ? "#e6af72" : "#829485"; font.pixelSize: 20; wrapMode: Text.Wrap }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; visible: !!parent.source.lastError; text: appWindow.localizedMessage(parent.source.lastError || ""); color: "#e6af72"; font.pixelSize: 18; wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight }
                        MetalButton { objectName: "source-refresh"; Layout.fillWidth: true; small: true; text: parent.source.updating ? qsTr("Updating configuration…") : qsTr("Update configuration"); enabled: backend.online && !parent.source.updating; onClicked: backend.refreshProfileSource(appWindow.selectedProfile.id) }
                    }
                    Item { Layout.fillHeight: true }
                    RowLayout {
                        MetalButton { text: qsTr("Remove"); danger: true; enabled: !backend.busy; onClicked: deleteDialog.open() }
                        Item { Layout.fillWidth: true }
                        MetalButton { objectName: "profile-save"; text: qsTr("Save"); enabled: renameField.text.trim().length > 0 && !backend.busy; onClicked: backend.updateProfile(appWindow.selectedProfile.id, renameField.text, appWindow.profileIconId) }
                    }
                }
                ColumnLayout {
                    spacing: 10
                    TerminalCheckBox { id: debugLogging; objectName: "debug-logging"; Layout.fillWidth: true; text: appWindow.isWork(appWindow.selectedProfile) ? qsTr("Detailed VPN logging") : qsTr("Detailed Xray logging"); onClicked: backend.setProfileDebug(appWindow.selectedProfile.id, checked) }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; objectName: "logs-hint"; text: !backend.online ? qsTr("Service unavailable — the last received log is shown.") : backend.logsError ? appWindow.localizedMessage(backend.logsError) : qsTr("Log detail changes at the next connection. History lasts 7 days. Up to 2,000 entries are shown and copied."); color: "#a5aa8c"; wrapMode: Text.Wrap; font.pixelSize: 18 }
                    Rectangle {
                        Layout.fillWidth: true; Layout.fillHeight: true
                        color: "#08110b"; border.color: "#625b40"; radius: 4
                        ListView {
                            id: logList; objectName: "profile-logs"
                            anchors.fill: parent; anchors.margins: 10
                            clip: true; spacing: 10; model: backend.profileLogs
                            delegate: Column {
                                required property var modelData
                                width: ListView.view.width - 10
                                Text { textFormat: Text.PlainText; width: parent.width; text: qsTr("%1 · %2").arg(appWindow.displayDateTime(parent.modelData.time)).arg(appWindow.logLevel(parent.modelData.level)); color: parent.modelData.level === "error" ? "#e1a183" : (parent.modelData.level === "warning" ? "#ddc279" : "#7f9e81"); font.family: appWindow.monoFont; font.pixelSize: 20; elide: Text.ElideRight }
                                Text { textFormat: Text.PlainText; objectName: "journal-message-" + parent.modelData.id; width: parent.width; text: parent.modelData.message; color: "#93d39a"; font.family: appWindow.monoFont; font.pixelSize: 22; wrapMode: Text.WrapAnywhere }
                            }
                            ScrollBar.vertical: ScrollBar {}
                        }
                    }
                    RowLayout {
                        MetalButton { objectName: "logs-older"; text: qsTr("Older"); small: true; implicitWidth: 124; enabled: backend.online && !backend.logActionPending && backend.logPreviousCursor.length > 0; onClicked: { appWindow.logHistoryMode = true; backend.loadOlderProfileLogs(appWindow.selectedProfile.id); logList.positionViewAtBeginning() } }
                        MetalButton { objectName: "logs-more"; text: qsTr("Latest"); small: true; implicitWidth: 160; enabled: backend.online && !backend.logActionPending; onClicked: { appWindow.logHistoryMode = false; appWindow.logFollowEnd = true; backend.loadProfileLogs(appWindow.selectedProfile.id, true); logList.positionViewAtEnd() } }
                        Item { Layout.fillWidth: true }
                        MetalButton { objectName: "logs-copy"; text: qsTr("Copy"); small: true; implicitWidth: 170; enabled: backend.profileLogs.length > 0; onClicked: backend.copyProfileLogs() }
                        MetalButton { objectName: "logs-clear"; text: qsTr("Clear"); small: true; implicitWidth: 160; danger: true; enabled: backend.online && !backend.logActionPending; onClicked: backend.clearProfileLogs(appWindow.selectedProfile.id) }
                    }
                }
                ColumnLayout {
                    spacing: 12
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Routes and DNS for this VPN profile"); color: "#a5d897"; font.pixelSize: 24; wrapMode: Text.Wrap }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("DNS servers: %1\nDomains: %2").arg((appWindow.profileRuntime(appWindow.selectedProfile).dnsServers || []).join(", ") || "—").arg((appWindow.profileRuntime(appWindow.selectedProfile).dnsDomains || []).join(", ") || "—"); color: "#b1aa92"; font.pixelSize: 20; wrapMode: Text.WrapAnywhere }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; visible: backend.workRoutesPending; text: qsTr("Refreshing routes…"); color: "#b1aa92"; font.pixelSize: 20 }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: appWindow.localizedMessage(backend.workRoutesError); color: "#e6af72"; wrapMode: Text.Wrap; font.pixelSize: 20; visible: text.length > 0 }
                    ListView {
                        objectName: "profile-routes"; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 12
                        model: (backend.workRoutes.items || []).filter(function(r) { return r.target === appWindow.selectedProfile.id })
                        delegate: Text { required property var modelData; width: ListView.view.width; textFormat: Text.PlainText; text: (modelData.domain || modelData.cidr || "") + "\n" + appWindow.routeState(modelData.state) + (modelData.message ? "\n" + appWindow.localizedMessage(modelData.message) : ""); color: modelData.conflict ? "#e6af72" : "#a5d897"; font.pixelSize: 22; wrapMode: Text.WrapAnywhere }
                        ScrollBar.vertical: ScrollBar {}
                    }
                    MetalButton { text: qsTr("Manage routes"); Layout.fillWidth: true; onClicked: appWindow.openRoutes() }
                }
                ColumnLayout {
                    spacing: 12
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: !backend.online ? qsTr("Service unavailable — showing the last received peer status.") : qsTr("A successful handshake confirms the peer, not access to every application. Idle peers do not need a recent handshake."); color: "#a5aa8c"; font.pixelSize: 20; wrapMode: Text.Wrap }
                    ListView {
                        id: peerList; objectName: "profile-peers"; Layout.fillWidth: true; Layout.fillHeight: true; spacing: 18; clip: true
                        model: appWindow.profileRuntime(appWindow.selectedProfile).peers || []
                        delegate: Column {
                            required property var modelData
                            required property int index
                            width: ListView.view.width - 14; spacing: 5
                            Text { objectName: "peer-state-" + parent.index; textFormat: Text.PlainText; width: parent.width; text: qsTr("Peer %1 · %2").arg(parent.index + 1).arg(appWindow.peerState(parent.modelData.state)); color: parent.modelData.state === "connected" ? "#a5d897" : "#e6af72"; font.pixelSize: 23; wrapMode: Text.Wrap }
                            Text { textFormat: Text.PlainText; width: parent.width; text: qsTr("Endpoint: %1").arg(parent.modelData.endpoint || "—"); color: "#b1aa92"; font.family: appWindow.monoFont; font.pixelSize: 21; wrapMode: Text.WrapAnywhere }
                            Text { objectName: "peer-handshake-" + parent.index; textFormat: Text.PlainText; width: parent.width; text: qsTr("Last handshake: %1").arg(parent.modelData.lastHandshakeAt ? appWindow.displayDateTime(Number(parent.modelData.lastHandshakeAt) * 1000) : qsTr("Not received yet")); color: "#b1aa92"; font.pixelSize: 20; wrapMode: Text.Wrap }
                            Text { textFormat: Text.PlainText; width: parent.width; text: qsTr("Allowed networks: %1").arg((parent.modelData.allowedIPs || []).join(", ") || "—"); color: "#93b39a"; font.family: appWindow.monoFont; font.pixelSize: 20; wrapMode: Text.WrapAnywhere }
                        }
                        ScrollBar.vertical: ScrollBar {}
                        Text { anchors.centerIn: parent; width: parent.width; visible: peerList.count === 0; text: backend.online ? qsTr("Connect the profile to see peer status.") : qsTr("Service unavailable — peer status is unknown."); textFormat: Text.PlainText; color: "#96a68d"; font.pixelSize: 22; wrapMode: Text.Wrap; horizontalAlignment: Text.AlignHCenter }
                    }
                }
            }
        }
    }
    Timer { interval: 2000; repeat: true; running: detailDialog.opened && profileTabs.currentIndex === 1 && backend.online && !appWindow.logHistoryMode; onTriggered: backend.loadProfileLogs(appWindow.selectedProfile.id) }
    TerminalDialog {
        id: deleteDialog; title: qsTr("Remove profile?"); height: 320
        ColumnLayout { anchors.fill: parent; spacing: 20
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Profile “%1” will be removed. Disconnect it first if it is in use.").arg(appWindow.selectedProfile.name || ""); color: "#d1b98d"; wrapMode: Text.Wrap; font.pixelSize: 23 }
            Item { Layout.fillHeight: true }
            RowLayout { Item { Layout.fillWidth: true } MetalButton { text: qsTr("Cancel"); onClicked: deleteDialog.close() } MetalButton { text: qsTr("Remove"); danger: true; enabled: !appWindow.profileActive(appWindow.selectedProfile) && !backend.busy; onClicked: { backend.removeProfile(appWindow.selectedProfile.id); deleteDialog.close() } } }
        }
    }

    TerminalDialog {
        id: settingsDialog; title: qsTr("Settings"); height: 858
        Binding { target: backend; property: "vpnCompatibilityActive"; value: settingsDialog.visible && settingsTabs.currentIndex === 2 && appWindow.visible && appWindow.visibility !== Window.Minimized && !diagnosticsDialog.visible && !errorDialog.visible }
        ColumnLayout {
            anchors.fill: parent; spacing: 12
            TabBar {
                id: settingsTabs; Layout.fillWidth: true
                TerminalTabButton { objectName: "launch-tab"; text: qsTr("General") } TerminalTabButton { objectName: "subscriptions-tab"; text: qsTr("Subscriptions") } TerminalTabButton { objectName: "vpn-tab"; text: qsTr("Other VPNs") }
            }
            StackLayout {
                currentIndex: settingsTabs.currentIndex; Layout.fillWidth: true; Layout.fillHeight: true
                ColumnLayout {
                    spacing: 18
                    RowLayout {
                        Layout.fillWidth: true; spacing: 18
                        Text { textFormat: Text.PlainText; text: qsTr("Language"); color: "#d6c49b"; font.pixelSize: 22 }
                        TerminalCombo {
                            id: languageSelector; objectName: "language-selector"
                            Layout.fillWidth: true
                            model: [{code: "system", name: qsTr("System default")}, {code: "en", name: "English"}, {code: "ru", name: "Русский"}]
                            textRole: "name"; valueRole: "code"
                            currentIndex: i18n.preference === "ru" ? 2 : i18n.preference === "en" ? 1 : 0
                            Accessible.name: qsTr("Language")
                            onActivated: i18n.setPreference(currentValue)
                        }
                    }
                    TerminalCheckBox { text: qsTr("Open the interface at login"); checked: backend.autostart; onClicked: backend.setAutostart(checked); palette.windowText: "#d6c49b"; font.pixelSize: 22 }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Connect before login"); color: "#8fd89a"; font.pixelSize: 24 }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("The system service connects the selected profile at boot. Only administrators can change this setting."); color: "#b1aa92"; font.pixelSize: 20; wrapMode: Text.Wrap }
                    TerminalCombo {
                        id: bootProfile; objectName: "boot-profile"; Layout.fillWidth: true
                        property string selectedProfileId: ""
                        property bool dirty: false
                        property bool missingSelection: false
                        model: backend.bootProfiles
                        firstItemText: qsTr("Off")
                        textRole: "name"; valueRole: "id"
                        function restoreSelection() {
                            const index = indexOfValue(selectedProfileId)
                            missingSelection = index < 0 && selectedProfileId.length > 0
                            currentIndex = index
                        }
                        function beginEdit() {
                            dirty = false
                            selectedProfileId = appWindow.snap.bootProfileId || ""
                            restoreSelection()
                        }
                        Component.onCompleted: beginEdit()
                        onModelChanged: Qt.callLater(restoreSelection)
                        onActivated: { selectedProfileId = currentValue || ""; dirty = true; missingSelection = false }
                        enabled: backend.online && !!appWindow.snap.canAdmin && !backend.bootPending; font.pixelSize: 21
                    }
                    Text { objectName: "boot-selection-missing"; textFormat: Text.PlainText; Layout.fillWidth: true; visible: bootProfile.missingSelection; text: qsTr("The selected profile was removed. Choose another profile or Off."); color: "#e6af72"; font.pixelSize: 20; wrapMode: Text.Wrap }
                    MetalButton { objectName: "boot-apply"; text: qsTr("Apply"); enabled: backend.online && !!appWindow.snap.canAdmin && !backend.bootPending && !bootProfile.missingSelection && bootProfile.currentIndex >= 0; onClicked: backend.setBootProfile(bootProfile.selectedProfileId) }
                    Text { textFormat: Text.PlainText; visible: !appWindow.snap.canAdmin; Layout.fillWidth: true; text: qsTr("This user cannot change the system startup settings."); color: "#c5a16c"; font.pixelSize: 20; wrapMode: Text.Wrap }
                    Item { Layout.fillHeight: true }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Closing the interface keeps the VPN running. Disconnect using the connection button or tray menu."); color: "#94a28c"; font.pixelSize: 20; wrapMode: Text.Wrap }
                }
                ColumnLayout {
                    spacing: 14
                    TerminalField { id: subscriptionName; objectName: "subscription-name"; Layout.fillWidth: true; placeholderText: qsTr("Subscription name"); maximumLength: 80 }
                    TerminalField { id: subscriptionUrl; objectName: "subscription-url"; Layout.fillWidth: true; placeholderText: "https://…"; echoMode: TextInput.PasswordEchoOnEdit; selectByMouse: true }
                    MetalButton { objectName: "subscription-prepare"; text: qsTr("Add"); enabled: subscriptionUrl.text.trim().length > 0 && subscriptionName.text.trim().length > 0 && !backend.busy; onClicked: appWindow.openSubscriptionImport() }
                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Subscription URLs may contain a secret token. They are not shown in diagnostics."); color: "#93a08a"; wrapMode: Text.Wrap; font.pixelSize: 18 }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; model: appWindow.snap.subscriptions || []; clip: true
                        delegate: Item {
                            required property var modelData
                            width: ListView.view.width; height: 76
                            Text { textFormat: Text.PlainText; width: parent.width-140; text: qsTr("%1\nUpdated: %2").arg(parent.modelData.name).arg(appWindow.formattedDate(parent.modelData.updatedAt)); color: "#c8bf9f"; font.pixelSize: 20; elide: Text.ElideRight }
                            MetalButton { anchors.right: parent.right; y: 7; text: qsTr("Remove"); small: true; danger: true; onClicked: { appWindow.selectedSubscription = parent.modelData; deleteSubscriptionDialog.open() } }
                        }
                        ScrollBar.vertical: ScrollBar {}
                    }
                    MetalButton { text: qsTr("Refresh all"); enabled: !backend.busy; onClicked: backend.refreshSubscriptions() }
                    Text { textFormat: Text.PlainText; id: subscriptionResult; text: !appWindow.subscriptionRefreshDone ? "" : (appWindow.subscriptionFailureCount > 0 ? qsTr("%1 subscriptions could not be updated. Existing profiles were kept; see diagnostics for details.").arg(appWindow.subscriptionFailureCount) : qsTr("Subscriptions updated.")); Layout.fillWidth: true; color: "#91ba90"; wrapMode: Text.Wrap; font.pixelSize: 19 }
                }
                ScrollView {
                    id: vpnScroll; objectName: "vpn-scroll"
                    contentWidth: availableWidth
                    clip: true
                    ColumnLayout {
                        width: vpnScroll.availableWidth; spacing: 13
                        MetalButton { objectName: "work-routes-open"; text: qsTr("Routes"); Layout.fillWidth: true; enabled: backend.online && !appWindow.snap.busyByOtherUser; onClicked: appWindow.openRoutes() }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Import .ovpn files from the main window. Work VPNs connect independently of the main VPN."); color: "#b1aa92"; font.pixelSize: 20; wrapMode: Text.Wrap }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Compatibility with other VPNs"); color: "#8fd89a"; font.pixelSize: 25 }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Pritunl is detected automatically. No fields need to be filled in."); color: "#c5b995"; font.pixelSize: 22; wrapMode: Text.Wrap }
                        Repeater {
                            model: backend.vpnCompatibility.items || []
                            delegate: Rectangle {
                                required property var modelData
                                required property int index
                                objectName: "vpn-detected-" + index
                                Layout.fillWidth: true; implicitHeight: vpnInfo.implicitHeight + 24
                                color: "#182019"; border.color: modelData.verified ? "#52634a" : "#8f6943"; radius: 5
                                ColumnLayout {
                                    id: vpnInfo; x: 12; y: 12; width: parent.width - 24; spacing: 6
                                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("%1 · %2").arg(appWindow.localizedMessage(modelData.application) || qsTr("Unknown VPN")).arg(modelData.interface); color: "#a5d897"; font.pixelSize: 23; wrapMode: Text.WrapAnywhere }
                                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: !modelData.verified ? qsTr("Verification failed") : modelData.source === "automatic" ? qsTr("Detected automatically · verified") : qsTr("Manual binding · verified"); color: modelData.verified ? "#c5b995" : "#e6af72"; font.pixelSize: 20; wrapMode: Text.Wrap }
                                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: !modelData.active ? qsTr("Tunnel is inactive") : !modelData.verified ? qsTr("Protection exceptions are not allowed") : modelData.fullIPv4 && modelData.fullIPv6 ? qsTr("Handles IPv4 and IPv6 internet traffic") : modelData.fullIPv4 ? qsTr("Handles IPv4 internet traffic") : modelData.fullIPv6 ? qsTr("Handles IPv6 internet traffic") : qsTr("Specific work routes only"); color: "#92a9bd"; font.pixelSize: 20; wrapMode: Text.Wrap }
                                    Text { textFormat: Text.PlainText; Layout.fillWidth: true; visible: text.length > 0; text: { i18n.language; return appWindow.localizedMessage(modelData.message || "") } color: "#d3b581"; font.pixelSize: 20; wrapMode: Text.Wrap }
                                }
                            }
                        }
                        Text { objectName: "vpn-discovery-status"; textFormat: Text.PlainText; Layout.fillWidth: true; visible: text.length > 0; text: { i18n.language; return appWindow.localizedMessage(backend.vpnCompatibilityError || backend.vpnCompatibility.message || "") || (backend.vpnCompatibility.busyByOtherUser ? qsTr("In use by another user") : backend.vpnCompatibilityPending ? qsTr("Checking tunnels…") : (backend.vpnCompatibility.items || []).length ? "" : qsTr("No active external VPNs found. Connect Pritunl, then open this tab.")) } color: backend.vpnCompatibilityError ? "#e6af72" : "#b9bc9e"; font.pixelSize: 20; wrapMode: Text.Wrap }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Work routes: Pritunl handles work networks; the main VPN handles the internet.\n\nFull tunnel: the requested main VPN connection waits while Pritunl handles the internet, then resumes when those routes are released. Pritunl settings stay unchanged."); color: "#c5b995"; font.pixelSize: 21; wrapMode: Text.Wrap }
                        MetalButton { objectName: "vpn-diagnostics"; text: qsTr("Diagnostics"); small: true; Layout.preferredWidth: 220; onClicked: appWindow.openDiagnostics() }
                        MetalButton { id: vpnAdvanced; objectName: "vpn-advanced"; Layout.fillWidth: true; checkable: true; text: (checked ? "▾ " : "▸ ") + qsTr("Advanced: manual binding"); onClicked: if (checked) Qt.callLater(function() { vpnScroll.contentItem.contentY = vpnAdvanced.y }) }
                        ColumnLayout {
                        visible: vpnAdvanced.checked; Layout.fillWidth: true; spacing: 13
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("For custom tunnels. The service verifies ownership and transport; an interface name alone is not enough."); color: "#b1aa92"; font.pixelSize: 20; wrapMode: Text.Wrap }
                        TerminalField { id: vpnInterface; Layout.fillWidth: true; placeholderText: qsTr("Interface, e.g. tun0"); maximumLength: 15 }
                        TerminalCombo { id: vpnManager; objectName: "vpn-manager"; Layout.fillWidth: true; model: ["networkmanager", "pritunl", "openvpn", "wg-quick"]; font.pixelSize: 21 }
                        TerminalField { id: vpnUnit; Layout.fillWidth: true; placeholderText: qsTr("systemd unit, e.g. openvpn-client@work.service") }
                        TerminalField { id: vpnCgroup; Layout.fillWidth: true; placeholderText: qsTr("Cgroup (if no systemd unit is specified)") }
                        Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("External VPN server"); color: "#d2c194"; font.pixelSize: 22 }
                        RowLayout {
                            TerminalField { id: vpnEndpoint; Layout.fillWidth: true; Layout.minimumWidth: 60; placeholderText: qsTr("IP address") }
                            TerminalField { id: vpnPort; Layout.preferredWidth: 112; placeholderText: qsTr("Port"); validator: IntValidator { bottom: 1; top: 65535 } }
                            TerminalCombo { id: vpnProtocol; objectName: "vpn-protocol"; model: ["udp", "tcp"]; Layout.preferredWidth: 95; font.pixelSize: 18 }
                        }
                        TerminalField { id: vpnMark; Layout.fillWidth: true; placeholderText: qsTr("WireGuard fwmark, e.g. 51820 (if used)") }
                        TerminalField { id: vpnRoutes; Layout.fillWidth: true; placeholderText: qsTr("Protected CIDRs, comma separated (split tunnel)") }
                        TerminalField { id: vpnDNS; Layout.fillWidth: true; placeholderText: qsTr("DNS servers, comma separated") }
                        TerminalField { id: vpnDomains; Layout.fillWidth: true; placeholderText: qsTr("DNS domains, comma separated, e.g. ~corp.example") }
                        RowLayout {
                            MetalButton { objectName: "vpn-save"; text: qsTr("Save binding"); Layout.preferredWidth: 300; Layout.preferredHeight: 60; enabled: !!appWindow.snap.canAdmin && vpnInterface.text.trim().length > 0 && !backend.busy; onClicked: {
                                var binding = {interface:vpnInterface.text.trim(), manager:vpnManager.currentText}
                                if (vpnUnit.text.trim()) binding.unit = vpnUnit.text.trim()
                                if (vpnCgroup.text.trim()) binding.cgroup = vpnCgroup.text.trim()
                                if (vpnEndpoint.text.trim()) binding.endpoints = [{address:vpnEndpoint.text.trim(), port:parseInt(vpnPort.text), protocol:vpnProtocol.currentText, mark:vpnMark.text.trim() ? Number(vpnMark.text) : 0}]
                                binding.routes = appWindow.splitLines(vpnRoutes.text)
                                binding.dnsServers = appWindow.splitLines(vpnDNS.text)
                                binding.dnsDomains = appWindow.splitLines(vpnDomains.text)
                                backend.setVPNBinding(binding)
                            } }
                            MetalButton { objectName: "vpn-delete"; text: qsTr("Remove"); Layout.preferredWidth: 300; Layout.preferredHeight: 60; danger: true; enabled: !!appWindow.snap.canAdmin && vpnInterface.text.trim().length > 0 && !backend.busy; onClicked: backend.setVPNBinding({interface:vpnInterface.text.trim(),manager:vpnManager.currentText,remove:true}) }
                        }
                        Text { textFormat: Text.PlainText; id: vpnResult; text: appWindow.vpnBindingSaved ? qsTr("Binding saved.") : ""; Layout.fillWidth: true; color: "#93c796"; font.pixelSize: 19; wrapMode: Text.Wrap }
                        }
                    }
                }
            }
            Text { objectName: "settings-version"; textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Vault 443 · version %1").arg(Qt.application.version); color: "#b4ab8b"; font.pixelSize: 20; horizontalAlignment: Text.AlignHCenter }
        }
        onOpened: { bootProfile.selectedProfileId = appWindow.snap.bootProfileId || ""; bootProfile.restoreSelection() }
    }

    TerminalDialog {
        id: routesDialog; objectName: "work-routes-dialog"; title: qsTr("Routes"); height: 870
        property string selectedRule: ""
        property string selectedTarget: "local"
        function editRule(rule) {
            routeKind.currentIndex = rule.domain ? 1 : 0
            routeDestination.text = rule.domain || rule.cidr || ""
            selectedRule = rule.manual ? rule.id : ""
            selectedTarget = rule.target || "local"
            Qt.callLater(routeTarget.restoreSelection)
        }
        ColumnLayout {
            anchors.fill: parent; spacing: 10
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Work VPN routes take priority over Docker. Select a destination to choose its VPN or local network. Removing a rule restores automatic selection."); color: "#bdb28e"; font.pixelSize: 20; wrapMode: Text.Wrap }
            RowLayout {
                TerminalCombo { id: routeKind; objectName: "work-route-kind"; Layout.preferredWidth: 190; model: [qsTr("Networks"), "DNS"]; onActivated: { routesDialog.selectedRule = ""; routeDestination.text = ""; routesDialog.selectedTarget = ""; Qt.callLater(routeTarget.restoreSelection) } }
                TerminalField { id: routeDestination; objectName: "work-route-destination"; Layout.fillWidth: true; maximumLength: 253; placeholderText: routeKind.currentIndex === 1 ? qsTr("Domain, e.g. corp.example") : qsTr("IP or CIDR, e.g. 192.168.100.15"); onTextEdited: routesDialog.selectedRule = "" }
            }
            TerminalCombo {
                id: routeTarget; objectName: "work-route-target"; Layout.fillWidth: true; textRole: "name"; valueRole: "id"
                model: (routeKind.currentIndex === 0 ? [{id:"local", name:qsTr("Local network / Docker")}] : []).concat(appWindow.snap.workProfiles || [])
                function restoreSelection() { currentIndex = Math.max(0, indexOfValue(routesDialog.selectedTarget)); routesDialog.selectedTarget = currentValue || "" }
                Component.onCompleted: restoreSelection()
                onModelChanged: Qt.callLater(restoreSelection)
                onActivated: routesDialog.selectedTarget = currentValue || ""
                Accessible.name: qsTr("Route destination")
            }
            RowLayout {
                MetalButton { objectName: "work-route-save"; text: qsTr("Save rule"); small: true; implicitWidth: 180; enabled: backend.online && !appWindow.snap.busyByOtherUser && !backend.workRoutesPending && routeDestination.text.trim().length > 0 && routeTarget.currentIndex >= 0 && !!routeTarget.currentValue; onClicked: { if (routeKind.currentIndex === 1) backend.setWorkDNS(routeDestination.text, routeTarget.currentValue); else backend.setWorkRoute(routeDestination.text, routeTarget.currentValue) } }
                MetalButton { objectName: "work-route-remove"; text: qsTr("Automatic"); small: true; implicitWidth: 220; enabled: !!routesDialog.selectedRule && !backend.workRoutesPending; onClicked: { if (routeKind.currentIndex === 1) backend.removeWorkDNS(routesDialog.selectedRule); else backend.removeWorkRoute(routesDialog.selectedRule); routesDialog.selectedRule = "" } }
                Item { Layout.fillWidth: true }
                MetalButton { objectName: "work-route-refresh"; text: qsTr("Refresh"); small: true; implicitWidth: 160; enabled: !backend.workRoutesPending; onClicked: backend.refreshWorkRoutes() }
            }
            Text { objectName: "work-routes-status"; textFormat: Text.PlainText; Layout.fillWidth: true; text: appWindow.localizedMessage(backend.workRoutesError || backend.workRoutes.message || "") || (backend.workRoutesPending ? qsTr("Refreshing routes…") : ""); visible: text.length > 0; color: backend.workRoutesError ? "#e6af72" : "#b1aa92"; font.pixelSize: 20; wrapMode: Text.Wrap; maximumLineCount: 3; elide: Text.ElideRight }
            ListView {
                id: workRouteList; objectName: "work-route-list"; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 9
                model: (routeKind.currentIndex === 1 ? (backend.workRoutes.dnsRules || []) : (backend.workRoutes.rules || [])).map(function(r) { var value = Object.assign({}, r); value.manual = true; return value }).concat((backend.workRoutes.items || []).filter(function(r) { return r.source !== "manual" && (routeKind.currentIndex === 1 ? !!r.domain : !!r.cidr) }))
                delegate: Button {
                    id: workRouteRow; required property var modelData; required property int index
                    objectName: "work-route-" + index; width: workRouteList.width; implicitHeight: routeDescription.implicitHeight + 22; padding: 11
                    PointerHover {}
                    background: Rectangle { color: workRouteRow.down ? "#233123" : "#152017"; border.color: workRouteRow.visualFocus ? "#a0e8a4" : workRouteRow.modelData.conflict ? "#9e774d" : "#52634a"; radius: 5 }
                    contentItem: Column {
                        id: routeDescription; spacing: 4
                        Text { textFormat: Text.PlainText; width: parent.width; text: (workRouteRow.modelData.domain || workRouteRow.modelData.cidr || "") + " → " + appWindow.routeTargetName(workRouteRow.modelData.target); color: "#9bdca0"; font.pixelSize: 23; wrapMode: Text.WrapAnywhere }
                        Text { textFormat: Text.PlainText; width: parent.width; text: (workRouteRow.modelData.manual ? qsTr("Manual rule") : appWindow.routeSource(workRouteRow.modelData.source)) + (workRouteRow.modelData.interface ? " · " + workRouteRow.modelData.interface : "") + (workRouteRow.modelData.state ? " · " + appWindow.routeState(workRouteRow.modelData.state) : ""); color: "#c0b38e"; font.pixelSize: 20; wrapMode: Text.Wrap }
                        Text { textFormat: Text.PlainText; width: parent.width; text: appWindow.localizedMessage(workRouteRow.modelData.message || ""); visible: text.length > 0; color: "#ddb078"; font.pixelSize: 19; wrapMode: Text.Wrap }
                    }
                    onClicked: routesDialog.editRule(modelData)
                }
                ScrollBar.vertical: ScrollBar {}
                Text { anchors.centerIn: parent; width: parent.width - 30; visible: workRouteList.count === 0 && !backend.workRoutesPending; text: qsTr("No work routes yet. Connect an OpenVPN, WireGuard or AmneziaWG profile."); textFormat: Text.PlainText; color: "#96a68d"; font.pixelSize: 22; wrapMode: Text.Wrap; horizontalAlignment: Text.AlignHCenter }
            }
        }
    }
    Timer { interval: 5000; repeat: true; running: routesDialog.visible && appWindow.visible && backend.online; onTriggered: backend.refreshWorkRoutes() }

    TerminalDialog {
        id: deleteSubscriptionDialog; title: qsTr("Remove subscription?"); height: 320
        ColumnLayout { anchors.fill: parent; spacing: 20
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; text: qsTr("Subscription “%1” will no longer be updated. Existing profiles and connections will be kept.").arg(appWindow.selectedSubscription.name || ""); color: "#d1b98d"; wrapMode: Text.Wrap; font.pixelSize: 23 }
            Item { Layout.fillHeight: true }
            RowLayout { Item { Layout.fillWidth: true } MetalButton { text: qsTr("Cancel"); onClicked: deleteSubscriptionDialog.close() } MetalButton { text: qsTr("Remove"); danger: true; enabled: !backend.busy; onClicked: { backend.removeSubscription(appWindow.selectedSubscription.id); deleteSubscriptionDialog.close() } } }
        }
    }
    TerminalDialog {
        id: diagnosticsDialog; objectName: "diagnostics-dialog"; title: qsTr("Diagnostics"); height: 830
        property var failure: {
            var value = backend.diagnosticData.lastFailure || appWindow.profileFailure(appWindow.diagnosticProfile)
            return !appWindow.diagnosticProfile.id || value.profileId === appWindow.diagnosticProfile.id ? value : ({})
        }
        ColumnLayout { anchors.fill: parent; spacing: 12
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; visible: !!appWindow.diagnosticProfile.id; text: appWindow.diagnosticProfile.name || ""; color: "#b8b08f"; elide: Text.ElideRight; font.pixelSize: 23 }
            Text {
                objectName: "diagnostics-state"
                textFormat: Text.PlainText; Layout.fillWidth: true
                text: { i18n.language; return backend.diagnosticsPending ? qsTr("Loading diagnostics…") : (appWindow.localizedMessage(backend.diagnosticsError) || qsTr("Snapshot received: %1").arg(appWindow.displayDateTime(backend.diagnosticsReceivedAt))) }
                color: backend.diagnosticsError.length ? "#e4a187" : "#a6ba91"; wrapMode: Text.Wrap; font.pixelSize: 22
            }
            Text {
                objectName: "diagnostics-failure"
                textFormat: Text.PlainText; Layout.fillWidth: true
                text: {
                    i18n.language
                    var failure = diagnosticsDialog.failure
                    if (failure.message) return qsTr("Last failure · %1\n%2").arg(appWindow.displayDateTime(Number(failure.time))).arg(appWindow.localizedMessage(failure.message))
                    if (backend.connectionError.length && (!appWindow.diagnosticProfile.id || appWindow.diagnosticProfile.id === backend.connectionErrorProfile)) return appWindow.localizedMessage(backend.connectionError)
                    return backend.diagnosticsPending ? "" : qsTr("No errors have been recorded for this profile.")
                }
                visible: text.length > 0
                color: "#e1b88f"; wrapMode: Text.Wrap; font.pixelSize: 22
                maximumLineCount: 5; elide: Text.ElideRight
            }
            Text {
                textFormat: Text.PlainText; Layout.fillWidth: true; visible: backend.diagnosticsError.length > 0
                text: qsTr("Last snapshot: %1").arg(backend.diagnosticsReceivedAt || backend.snapshotReceivedAt ? appWindow.displayDateTime(backend.diagnosticsReceivedAt || backend.snapshotReceivedAt) : qsTr("not received yet"))
                color: "#a6aa8a"; font.pixelSize: 20; wrapMode: Text.Wrap
            }
            ScrollView { Layout.fillWidth: true; Layout.fillHeight: true
                TextArea { objectName: "diagnostics-summary"; text: backend.diagnostics; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; wrapMode: TextEdit.WrapAnywhere; color: "#90d39a"; font.family: appWindow.monoFont; font.pixelSize: 20; background: Rectangle { color: "#08100b"; border.color: "#63573f" } }
            }
            RowLayout {
                MetalButton { objectName: "diagnostics-refresh"; text: qsTr("Refresh"); implicitWidth: 210; enabled: !backend.diagnosticsPending; onClicked: backend.getDiagnostics(appWindow.diagnosticProfile.id || "") }
                MetalButton { objectName: "diagnostics-logs"; text: qsTr("Logs"); implicitWidth: 150; enabled: backend.online && !!appWindow.diagnosticProfile.id; onClicked: { diagnosticsDialog.close(); appWindow.showProfile(appWindow.diagnosticProfile); profileTabs.currentIndex = 1 } }
                Item { Layout.fillWidth: true }
                MetalButton { objectName: "diagnostics-copy"; text: qsTr("Copy"); enabled: backend.diagnostics.length > 0; onClicked: backend.copyDiagnostics() }
            }
        }
    }
    TerminalDialog {
        id: errorDialog; objectName: "error-dialog"; title: qsTr("Action failed"); height: 365
        ColumnLayout { anchors.fill: parent; spacing: 20
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; Layout.fillHeight: true; text: { i18n.language; return appWindow.localizedMessage(backend.error) || (backend.demo ? qsTr("Could not connect to the server. Network protection remains active; reconnection is automatic.") : "") } color: "#e0b195"; font.pixelSize: 22; wrapMode: Text.Wrap }
            RowLayout { MetalButton { text: qsTr("Diagnostics"); onClicked: { errorDialog.close(); appWindow.openDiagnostics() } } Item { Layout.fillWidth: true } MetalButton { text: qsTr("Got it"); onClicked: { errorDialog.close(); backend.clearError() } } }
        }
    }
    TerminalDialog {
        id: takeoverDialog; title: qsTr("Take over VPN"); height: 390
        ColumnLayout { anchors.fill: parent; spacing: 20
            Text { textFormat: Text.PlainText; Layout.fillWidth: true; Layout.fillHeight: true; text: qsTr("Another user is using the VPN. Taking control disconnects all their main and work VPN connections. You can then connect your own profiles."); color: "#d5ba91"; wrapMode: Text.Wrap; font.pixelSize: 23 }
            RowLayout { MetalButton { text: qsTr("Cancel"); onClicked: takeoverDialog.close() } Item { Layout.fillWidth: true } MetalButton { text: qsTr("Take control"); danger: true; enabled: backend.online && !backend.networkBusy; onClicked: { backend.takeControl(); takeoverDialog.close() } } }
        }
    }
}
