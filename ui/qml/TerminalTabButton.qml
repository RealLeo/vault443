import QtQuick
import QtQuick.Controls

TabButton {
    id: control
    PointerHover {}
    implicitHeight: 45
    font.family: "DejaVu Sans Condensed"
    font.pixelSize: 21
    contentItem: Text { textFormat: Text.PlainText; text: control.text; font: control.font; color: control.checked ? "#a0e8a4" : "#c3b185"; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
    background: Rectangle { color: control.checked ? "#203124" : "#171c17"; border.color: control.visualFocus ? "#a0e8a4" : "#766344"; radius: 4 }
}
