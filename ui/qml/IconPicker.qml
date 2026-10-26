import QtQuick
import QtQuick.Controls

TerminalDialog {
    id: picker
    title: qsTr("Profile emblem")
    width: 660; height: 770
    property string selectedIcon: "antenna"
    signal chosen(string iconId)
    readonly property var icons: [
        {id:"antenna",name:qsTr("Antenna")},{id:"dish",name:qsTr("Dish")},{id:"globe",name:qsTr("Globe")},
        {id:"vault-door",name:qsTr("Vault door")},{id:"radiation",name:qsTr("Radiation")},{id:"atom",name:qsTr("Atom")},
        {id:"gear",name:qsTr("Gear")},{id:"wrench",name:qsTr("Wrench")},{id:"lightning",name:qsTr("Lightning")},
        {id:"battery",name:qsTr("Battery")},{id:"shield",name:qsTr("Shield")},{id:"key",name:qsTr("Key")},
        {id:"gas-mask",name:qsTr("Gas mask")},{id:"crt-terminal",name:qsTr("Terminal")},{id:"robot",name:qsTr("Robot")},
        {id:"radar",name:qsTr("Radar")},{id:"compass",name:qsTr("Compass")},{id:"rocket",name:qsTr("Rocket")},
        {id:"canteen",name:qsTr("Canteen")},{id:"vacuum-tube",name:qsTr("Vacuum tube")},{id:"plug",name:qsTr("Plug")},
        {id:"binoculars",name:qsTr("Binoculars")},{id:"satellite",name:qsTr("Satellite")}
    ]
    GridView {
        id: grid
        objectName: "icon-grid"
        anchors.fill: parent
        cellWidth: width / 5; cellHeight: 132
        clip: true
        model: picker.visible ? picker.icons : []
        ScrollBar.vertical: ScrollBar {}
        delegate: Button { PointerHover {}
            required property var modelData
            objectName: "icon-" + modelData.id
            width: grid.cellWidth - 6; height: grid.cellHeight - 6
            padding: 5
            Accessible.name: modelData.name
            background: Rectangle { color: parent.down ? "#09110b" : (parent.hovered ? "#2d3527" : "#171d17"); radius: 6; border.width: 2; border.color: parent.visualFocus ? "#a0e8a4" : (picker.selectedIcon === parent.modelData.id ? "#b99c5d" : "#514c37") }
            contentItem: Column {
                ProfileIcon { anchors.horizontalCenter: parent.horizontalCenter; width: 88; height: 89; iconId: modelData.id }
                Text { textFormat: Text.PlainText; width: parent.width; height: 22; text: modelData.name; font.pixelSize: 16; font.family: "DejaVu Sans Condensed"; color: "#d5c08b"; elide: Text.ElideRight; horizontalAlignment: Text.AlignHCenter }
            }
            onClicked: { picker.chosen(modelData.id); picker.close() }
        }
    }
}
