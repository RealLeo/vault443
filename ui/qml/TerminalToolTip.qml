import QtQuick
import QtQuick.Controls

ToolTip {
    id: tip
    property Item control
    parent: Overlay.overlay
    scale: initialScale
    transformOrigin: Item.TopLeft
    width: Math.min(670, parent.width / scale - 16)
    padding: 14
    delay: 700
    visible: control && control.hovered && !control.down
    x: control ? Math.max(4, Math.min(parent.width - width * scale - 4, control.mapToItem(parent, control.width / 2, 0).x - width * scale / 2)) : 4
    y: {
        if (!control) return 4
        var top = control.mapToItem(parent, 0, 0).y - height * scale - 4
        return top >= 4 ? top : control.mapToItem(parent, 0, control.height).y + 4
    }
    background: Rectangle { color: "#20271d"; border.color: "#a28a5c"; radius: 5 }
    contentItem: Text { text: tip.text; textFormat: Text.PlainText; wrapMode: Text.Wrap; color: "#e2c690"; font.family: "DejaVu Sans Condensed"; font.pixelSize: 22 }
}
