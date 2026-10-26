import QtQuick
import QtQuick.Controls

TextField {
    id: control
    implicitHeight: 48
    color: "#91eaa0"
    placeholderTextColor: "#63756b"
    selectionColor: "#396844"
    selectedTextColor: "#eff7e9"
    font.family: "DejaVu Sans Mono"
    font.pixelSize: 19
    padding: 12
    background: Rectangle {
        color: "#09120c"
        radius: 4
        border.color: control.activeFocus ? "#89d895" : "#655b44"
        border.width: 1
    }
}
