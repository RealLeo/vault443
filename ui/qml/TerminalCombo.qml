import QtQuick
import QtQuick.Controls

ComboBox {
    id: control
    property string firstItemText: ""
    displayText: currentIndex === 0 && firstItemText.length ? firstItemText : currentText
    PointerHover {}
    implicitHeight: 49
    leftPadding: 12
    rightPadding: 38
    font.family: "DejaVu Sans Condensed"
    font.pixelSize: 21
    contentItem: Text { textFormat: Text.PlainText; text: control.displayText; color: control.enabled ? "#d8c395" : "#7a7966"; font: control.font; verticalAlignment: Text.AlignVCenter; elide: Text.ElideRight }
    indicator: Text { textFormat: Text.PlainText; x: parent.width-29; anchors.verticalCenter: parent.verticalCenter; width: 24; height: 35; text: "▾"; color: "#d2b471"; font.pixelSize: 26; verticalAlignment: Text.AlignVCenter }
    background: Rectangle { color: control.down ? "#16241a" : "#0b150e"; radius: 4; border.color: control.visualFocus ? "#90db99" : "#76664a" }
    delegate: ItemDelegate {
        PointerHover {}
        width: control.popup.width - 4
        height: 49
        leftPadding: 12; rightPadding: 12
        text: index === 0 && control.firstItemText.length ? control.firstItemText : (control.textRole ? modelData[control.textRole] : modelData)
        font: control.font
        highlighted: control.highlightedIndex === index
        contentItem: Text { textFormat: Text.PlainText; text: parent.text; color: "#d3c092"; font: control.font; elide: Text.ElideRight; verticalAlignment: Text.AlignVCenter }
        background: Rectangle { color: parent.highlighted ? "#304b32" : "#172019" }
    }
    popup: Popup {
        id: menu
        objectName: control.objectName + "-popup"
        parent: Overlay.overlay
        // The overlay is outside the scaled scene/dialog; apply its scale once.
        scale: initialScale
        transformOrigin: Item.TopLeft
        width: Math.min(control.width, parent.width / scale - 8)
        implicitHeight: Math.min(contentItem.implicitHeight + 4, 320, parent.height / scale - 8)
        padding: 2
        onAboutToShow: {
            const bottom = control.mapToItem(parent, 0, control.height)
            const top = control.mapToItem(parent, 0, 0)
            x = Math.max(2, Math.min(bottom.x, parent.width - width * scale - 2))
            const below = bottom.y + 2 * scale
            y = Math.max(2, Math.min(below + height * scale <= parent.height - 2 ? below : top.y - height * scale - 2 * scale, parent.height - height * scale - 2))
        }
        contentItem: ListView { clip: true; implicitHeight: contentHeight; model: menu.visible ? control.delegateModel : null; currentIndex: control.highlightedIndex; ScrollIndicator.vertical: ScrollIndicator {} }
        background: Rectangle { color: "#182219"; border.color: "#8e7d56"; radius: 4 }
    }
}
