import QtQuick

// A passive pointer handler: clicks, scrolling and keyboard focus stay with the control.
HoverHandler {
    objectName: "pointer-hover"
    cursorShape: parent && parent.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
}
