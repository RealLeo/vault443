import QtQuick
import QtQuick.Controls

Item {
    property var host
    property bool preview: false
    readonly property string profileId: modelData.id || ""
    signal dragStarted(var source, point position, real offset)
    signal dragMoved(point position)
    signal dragFinished(point position)
    signal dragCancelled()
    function focusControl(kind) {
        for (var i=0;i<children.length;i++) {
            if (children[i].objectName === kind + "-" + index) {
                children[i].forceActiveFocus(Qt.OtherFocusReason); return
            }
        }
    }
    id: row
    required property var modelData
    required property int index
    width: 872; height: variant === 0 ? 185 : 190
    property int variant: Math.max(0, index) % 3
    property int cardHeight: [182, 186, 190][variant]
    property bool active: host.profileActive(modelData)
    property bool lit: active && host.profileRuntime(modelData).state === "connected"
    Image { width: parent.width; height: row.cardHeight; source: "qrc:/assets/skin/card-" + (row.variant + 1) + ".png" }
    Image { x: 221; y: row.variant === 0 ? 88 : 93; width: 54; height: 53; source: "qrc:/assets/skin/led-" + (row.lit ? "on" : "off") + ".png" }
    Text { textFormat: Text.PlainText;
        x: 223; y: [41,42,41][row.variant]; width: 302; height: 43
        text: row.modelData.name || qsTranslate("Main", "Profile")
        color: "#78df8a"
        font.family: host.monoFont; font.pixelSize: 40; font.letterSpacing: 0.6
        elide: Text.ElideRight
        verticalAlignment: Text.AlignVCenter
    }
    Text { objectName: "profile-kind-" + row.index; x: 224; y: [20,21,20][row.variant]; width: 302; height: 20; text: host.protocolName(row.modelData); textFormat: Text.PlainText; color: "#90a68a"; font.family: host.bodyFont; font.pixelSize: 18 }
    Button { PointerHover {}
        id: profileStatus
        objectName: "status-" + row.index
        x: 283; y: row.variant === 0 ? 86 : 93; width: 250; height: 64
        padding: 0; hoverEnabled: true
        text: host.statusText(row.modelData)
        Accessible.name: host.statusDetail(row.modelData)
        background: Rectangle { color: "transparent"; border.color: profileStatus.visualFocus ? "#a0e8a4" : "transparent"; radius: 3 }
        contentItem: Text {
            textFormat: Text.PlainText; text: profileStatus.text
            color: row.lit ? "#78df8a" : (row.active ? "#d6b468" : "#708985")
            font.family: host.monoFont; font.pixelSize: text.length > 18 ? 22 : 30; font.letterSpacing: 0.1
            wrapMode: Text.Wrap
            elide: Text.ElideRight; verticalAlignment: Text.AlignVCenter
            maximumLineCount: 2
        }
        TerminalToolTip { control: profileStatus; text: host.statusDetail(row.modelData) }
        onClicked: host.openDiagnostics(row.modelData)
    }
    Button { PointerHover {}
        id: connectionButton
        objectName: "connect-" + row.index
        x: 588; y: row.variant === 0 ? 43 : 48; width: 247; height: row.variant === 0 ? 88 : 89
        enabled: host.canActivate(row.modelData)
        hoverEnabled: true
        padding: 0
        Accessible.name: qsTranslate("Main", "%1 %2").arg(host.connectionLabel(row.modelData)).arg(row.modelData.name)
        text: host.connectionLabel(row.modelData)
        background: Item {
            Image { anchors.fill: parent; source: "qrc:/assets/skin/button-" + (row.active ? "red" : "green") + ".png" }
            Rectangle { anchors.fill: parent; anchors.margins: 5; radius: 9; color: connectionButton.down ? "#33000000" : (connectionButton.hovered ? "#14ffeead" : "transparent"); border.color: connectionButton.visualFocus ? "#d3eab0" : "transparent"; border.width: 2 }
        }
        contentItem: Text { textFormat: Text.PlainText;
            text: connectionButton.text
            color: connectionButton.enabled || row.preview ? "#e7c68a" : "#aa9570"
            font.family: host.monoFont; font.pixelSize: text.length > 10 ? 30 : 38; font.letterSpacing: 0.1
            horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
        }
        onClicked: host.activateProfile(row.modelData)
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
        Accessible.name: qsTranslate("Main", "Profile details: %1").arg(row.modelData.name)
        ToolTip.visible: hovered; ToolTip.text: qsTranslate("Main", "Name, emblem and connection logs")
        onClicked: host.showProfile(row.modelData)
    }
    TapHandler { acceptedButtons: Qt.RightButton; onTapped: host.showProfile(row.modelData) }
    Item {
        id: grip
        objectName: "grip-" + row.index
        x: 0; y: (row.cardHeight - height) / 2; width: 28; height: 64
        enabled: backend.profileModel.count > 1
        Accessible.role: Accessible.Button
        Accessible.name: qsTr("Move profile %1").arg(row.modelData.name)
        Column {
            anchors.centerIn: parent; anchors.alignWhenCentered: false; spacing: 7
            Repeater {
                model: 3
                Rectangle {
                    objectName: "grip-dot"
                    width: 5; height: 5; radius: 2.5
                    color: grip.enabled ? "#97835a" : "#514c3e"
                }
            }
        }
        MouseArea {
            id: gripMouse
            objectName: "grip-mouse-" + row.index
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton; hoverEnabled: true; preventStealing: true
            cursorShape: !grip.enabled ? Qt.ArrowCursor : moving ? Qt.ClosedHandCursor : Qt.OpenHandCursor
            property point pressPoint
            property real grabOffset: 0
            property bool moving: false
            onPressed: function(mouse) {
                pressPoint = mapToItem(null, mouse.x, mouse.y)
                grabOffset = grip.y + mouse.y; moving = false
            }
            onPositionChanged: function(mouse) {
                if (!pressed) return
                var point = mapToItem(null, mouse.x, mouse.y)
                var dx = point.x - pressPoint.x, dy = point.y - pressPoint.y
                if (!moving && Math.sqrt(dx*dx+dy*dy) >= Qt.styleHints.startDragDistance) {
                    moving = true; row.dragStarted(row, point, grabOffset)
                }
                if (moving) row.dragMoved(point)
            }
            onReleased: function(mouse) {
                if (moving) row.dragFinished(mapToItem(null, mouse.x, mouse.y))
                moving = false
            }
            onCanceled: { moving = false; row.dragCancelled() }
        }
    }
}
