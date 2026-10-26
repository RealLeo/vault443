import QtQuick
import QtQuick.Controls

Popup {
    id: dialog
    property string title: ""
    default property alias body: bodyItem.data
    parent: Overlay.overlay
    width: 804
    height: 752
    scale: initialScale
    transformOrigin: Item.TopLeft
    x: (parent.width - width * scale) / 2
    y: (parent.height - height * scale) / 2
    padding: 0
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape
    Overlay.modal: Rectangle { color: "#ae000000" }
    background: Rectangle {
        color: "#252722"
        radius: 10
        border.width: 3
        border.color: "#968366"
        Image { anchors.fill: parent; anchors.margins: 9; source: "qrc:/assets/skin/window.png"; sourceClipRect: Qt.rect(310, 88, 460, 68); fillMode: Image.Tile; opacity: 0.16 }
        Rectangle { anchors.fill: parent; anchors.margins: 7; color: "transparent"; border.color: "#10120e"; border.width: 3; radius: 6 }
    }
    contentItem: Item {
        Text { textFormat: Text.PlainText;
            x: 25; y: 20; width: parent.width-100
            text: dialog.title
            color: "#e5c586"
            font.family: "DejaVu Sans Condensed"
            font.pixelSize: 29
            font.bold: true
            elide: Text.ElideRight
        }
        MetalButton { x: parent.width-64; y: 14; width: 45; height: 45; small: true; text: "×"; danger: true; onClicked: dialog.close(); Accessible.name: qsTr("Close dialog") }
        Rectangle { x: 22; y: 66; width: parent.width-44; height: 1; color: "#645b46" }
        Item { id: bodyItem; x: 25; y: 84; width: parent.width-50; height: parent.height-109 }
    }
}
