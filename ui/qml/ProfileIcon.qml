import QtQuick

Item {
    id: icon
    property string iconId: "antenna"
    property bool framed: true
    readonly property bool preframed: ["antenna", "dish", "globe"].indexOf(iconId) >= 0
    implicitWidth: 114
    implicitHeight: 115
    Image {
        anchors.fill: parent
        visible: icon.framed || icon.preframed
        source: icon.preframed ? "qrc:/assets/skin/emblem-" + icon.iconId + ".png" : "qrc:/assets/profile-icons/blank.png"
        fillMode: Image.Stretch
    }
    Image {
        anchors.centerIn: parent
        width: parent.width * 0.73; height: parent.height * 0.73
        visible: !icon.preframed
        source: icon.preframed ? "" : "qrc:/assets/profile-icons/" + icon.iconId + ".png"
        fillMode: Image.PreserveAspectFit
        sourceSize: Qt.size(192, 192)
        mipmap: true
    }
}
