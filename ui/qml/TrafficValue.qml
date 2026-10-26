import QtQuick

Text {
    id: value
    property string description
    property string explanation
    readonly property bool hovered: hover.hovered
    readonly property bool down: false
    textFormat: Text.PlainText
    color: "#82db96"
    font.pixelSize: 24
    horizontalAlignment: Text.AlignHCenter
    verticalAlignment: Text.AlignVCenter
    elide: Text.ElideRight
    HoverHandler { id: hover }
    Accessible.role: Accessible.StaticText
    Accessible.name: description
    TerminalToolTip { control: value; text: value.description + "\n" + value.explanation }
}
