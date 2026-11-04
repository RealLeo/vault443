import QtQuick
import QtQuick.Controls

ScrollBar {
    id: control
    property bool overflowing: false
    orientation: Qt.Vertical
    policy: ScrollBar.AlwaysOn
    active: true
    interactive: overflowing
    minimumSize: height > 0 ? Math.min(1, 48/height) : 1
    padding: 0; leftPadding: 7; rightPadding: 7
    hoverEnabled: true
    Accessible.name: qsTr("Scroll profiles")
    background: Item {
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter; width: 6; height: parent.height; radius: 3
            color: "#121812"; border.color: "#574e37"; border.width: 1
        }
    }
    contentItem: Rectangle {
        objectName: "profile-scroll-thumb"
        implicitWidth: 6; implicitHeight: 48; radius: 3
        opacity: 1
        gradient: Gradient {
            GradientStop { position: 0; color: !control.overflowing ? "#494b37" : control.pressed ? "#d0ba7f" : control.hovered ? "#b7a56e" : "#8f8d5d" }
            GradientStop { position: 1; color: !control.overflowing ? "#333b2e" : control.pressed ? "#8e8855" : control.hovered ? "#7d8052" : "#596246" }
        }
        border.width: 1; border.color: control.overflowing ? "#b3a06a" : "#5d5a40"
    }
    HoverHandler { cursorShape: control.overflowing ? (control.pressed ? Qt.ClosedHandCursor : Qt.PointingHandCursor) : Qt.ArrowCursor }
    // ScrollBar's default track click centers the thumb. Explicit page steps
    // keep this narrow control predictable without changing thumb dragging.
    MouseArea {
        anchors.fill: parent
        enabled: control.overflowing
        acceptedButtons: Qt.LeftButton
        preventStealing: true
        onPressed: function(mouse) {
            var y = mouse.y/control.height
            if (y < control.visualPosition) control.decrease()
            else if (y > control.visualPosition+control.visualSize) control.increase()
            else mouse.accepted = false // Let ScrollBar drag the thumb normally.
        }
    }
}
