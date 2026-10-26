import QtQuick
import QtQuick.Controls

CheckBox {
    id: control
    PointerHover {}
    implicitHeight: 48
    spacing: 12
    font.family: "DejaVu Sans Condensed"
    font.pixelSize: 22
    indicator: Image { x: control.leftPadding; anchors.verticalCenter: parent.verticalCenter; width: 37; height: 36; source: "qrc:/assets/skin/checkbox-" + (control.checked ? "on" : "off") + ".png" }
    contentItem: Text { textFormat: Text.PlainText; text: control.text; font: control.font; color: control.enabled ? "#d6c49b" : "#857f67"; leftPadding: 49; verticalAlignment: Text.AlignVCenter; wrapMode: Text.Wrap }
    background: Rectangle { color: "transparent"; border.color: control.visualFocus ? "#83d58e" : "transparent"; radius: 4 }
}
