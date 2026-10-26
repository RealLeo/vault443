import QtQuick
import QtQuick.Controls

Button {
    id: control
    PointerHover {}
    property bool danger: false
    property bool small: false
    property string faceFont: "DejaVu Sans Condensed"
    implicitWidth: small ? 124 : 220
    implicitHeight: small ? 42 : 60
    padding: 10
    hoverEnabled: true
    font.family: faceFont
    font.pixelSize: small ? 19 : 25
    Accessible.name: text
    contentItem: Text { textFormat: Text.PlainText;
        text: control.text
        font: control.font
        color: control.enabled ? "#edcc86" : "#847862"
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: 7
        border.width: control.visualFocus ? 2 : 1
        border.color: control.visualFocus ? "#8eee9b" : (control.hovered ? "#dfbc73" : "#77674a")
        gradient: Gradient {
            GradientStop { position: 0; color: control.down ? "#121810" : (control.danger ? "#693226" : "#34442b") }
            GradientStop { position: 1; color: control.danger ? "#381b16" : "#172015" }
        }
        Rectangle { anchors.fill: parent; anchors.margins: 4; radius: 4; color: "transparent"; border.color: "#332d21" }
    }
}
