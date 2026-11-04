import QtQuick
import QtQuick.Controls

Item {
    id: root
    objectName: "profile-list-controller"
    required property var host
    property string draggingId: ""
    property var dragSource: null
    property var dragData: ({})
    property int dragIndex: 0
    property point pointerPosition
    property real grabOffset: 0
    property string beforeId: ""
    property real insertY: 0
    property var savedView: null
    property int viewGeneration: 0
    readonly property bool inside: pointerPosition.x >= 0 && pointerPosition.x < width && pointerPosition.y >= 0 && pointerPosition.y <= height

    function clampScroll(value) {
        return Math.max(list.originY, Math.min(value, list.originY + Math.max(0, list.contentHeight-list.height)))
    }
    function captureView() {
        var i = list.indexAt(1, list.contentY+1)
        if (i < 0) i = 0
        if (backend.profileModel.idAt(i) === draggingId && i+1 < list.count) i++
        var item = list.itemAtIndex(i)
        var focus = host.activeFocusItem, kind = "", id = ""
        while (focus) {
            if (/^(profile|connect|status)-\d+$/.test(focus.objectName)) kind = focus.objectName.replace(/-\d+$/, "")
            if (focus.profileId !== undefined) { id = focus.profileId; break }
            focus = focus.parent
        }
        savedView = { anchor: backend.profileModel.idAt(i), offset: item ? item.y-list.contentY : 0,
            contentY: list.contentY, focusId: draggingId ? "" : id, focusKind: draggingId ? "" : kind }
    }
    function restoreView() {
        var state = savedView
        savedView = null
        if (!state) return
        var generation = ++viewGeneration
        Qt.callLater(function() {
            if (generation !== viewGeneration) return
            list.forceLayout()
            var index = backend.profileModel.indexOf(state.anchor)
            if (index >= 0) list.positionViewAtIndex(index, ListView.Beginning)
            var anchor = index >= 0 ? list.itemAtIndex(index) : null
            list.contentY = clampScroll(anchor ? anchor.y-state.offset : state.contentY)
            var focusIndex = backend.profileModel.indexOf(state.focusId)
            if (!root.draggingId && focusIndex >= 0 && state.focusKind) {
                list.positionViewAtIndex(focusIndex, ListView.Contain)
                var focusedRow = list.itemAtIndex(focusIndex)
                if (focusedRow) focusedRow.focusControl(state.focusKind)
            } else if (!root.draggingId && state.focusId) list.forceActiveFocus(Qt.OtherFocusReason)
        })
    }
    function beginDrag(source, position, offset) {
        cancelDrag()
        dragSource = source; draggingId = source.profileId; grabOffset = offset
        dragData = source.modelData; dragIndex = source.index
        pointerPosition = root.mapFromItem(null, position.x, position.y)
        updateTarget()
    }
    function moveDrag(position) {
        if (!draggingId) return
        pointerPosition = root.mapFromItem(null, position.x, position.y)
        updateTarget()
    }
    function updateTarget() {
        if (!draggingId || !inside) return
        var index = list.indexAt(1, list.contentY + pointerPosition.y)
        if (index < 0) index = pointerPosition.y < height/2 ? 0 : list.count
        var item = list.itemAtIndex(index)
        if (item && list.contentY + pointerPosition.y > item.y + item.height/2) index++
        beforeId = backend.profileModel.idAt(index)
        var next = list.itemAtIndex(index)
        var previous = list.itemAtIndex(index-1)
        insertY = Math.max(0, Math.min(height-2, next ? next.y-list.contentY : previous ? previous.y+previous.height-list.contentY : height-2))
    }
    function finishDrag(position) {
        if (!draggingId) return
        moveDrag(position)
        var id = draggingId, before = beforeId
        if (inside) backend.profileModel.moveBefore(id, before)
        cancelDrag()
    }
    function cancelDrag() {
        draggingId = ""; dragSource = null; dragData = ({}); beforeId = ""
    }
    Connections {
        target: backend.profileModel
        function onViewAboutToChange(membershipChanged) {
            if (membershipChanged) root.cancelDrag()
            root.captureView()
        }
        function onChanged() { root.restoreView() }
    }
    Connections {
        target: root.host
        function onActiveChanged() { if (!root.host.active) root.cancelDrag() }
        function onVisibleChanged() { if (!root.host.visible) root.cancelDrag() }
    }
    Shortcut { sequence: "Escape"; enabled: root.draggingId !== ""; onActivated: root.cancelDrag() }
    ListView {
        id: list
        objectName: "profile-list"
        anchors.fill: parent
        clip: true; spacing: 0
        boundsBehavior: Flickable.StopAtBounds
        interactive: root.draggingId === ""
        // Retain the MouseArea owning the pointer grab during edge scrolling.
        cacheBuffer: root.draggingId ? contentHeight : height
        model: backend.profileModel
        delegate: ProfileCard {
            host: root.host
            opacity: root.draggingId === profileId ? 0.4 : 1
            onDragStarted: function(source, position, offset) { root.beginDrag(source, position, offset) }
            onDragMoved: function(position) { root.moveDrag(position) }
            onDragFinished: function(position) { root.finishDrag(position) }
            onDragCancelled: root.cancelDrag()
        }
        ScrollBar.vertical: ProfileScrollBar {
            objectName: "profile-scrollbar"
            parent: root
            x: root.width-4; y: 0; height: root.height; width: 20
            overflowing: list.contentHeight > list.height
            stepSize: list.contentHeight > 0 ? list.height/list.contentHeight : 1
        }
    }
    Item {
        anchors.fill: parent; clip: true
        Loader {
            objectName: "profile-drag-preview"
            active: root.draggingId !== ""
            visible: active
            enabled: false
            sourceComponent: ProfileCard {
                host: root.host; modelData: root.dragData; index: root.dragIndex
                preview: true
            }
            width: root.width; height: root.dragSource ? root.dragSource.height : 0
            y: Math.max(0, Math.min(root.height-height, root.pointerPosition.y-root.grabOffset))
            opacity: 0.85
        }
        Rectangle {
            objectName: "profile-drop-marker"
            visible: root.draggingId !== "" && root.inside
            x: 4; y: root.insertY; width: root.width-8; height: 2; color: "#d4bb7b"
        }
    }
    Timer {
        interval: 16; repeat: true; running: root.draggingId !== "" && root.inside
        property double lastTick: 0
        onRunningChanged: lastTick = Date.now()
        onTriggered: {
            var now = Date.now(), dt = Math.min(0.05, (now-lastTick)/1000)
            lastTick = now
            var edge = 40, y = root.pointerPosition.y
            var velocity = y < edge ? -(edge-y)/edge : y > root.height-edge ? (y-root.height+edge)/edge : 0
            if (velocity !== 0) { list.contentY = root.clampScroll(list.contentY + velocity*480*dt); root.updateTarget() }
        }
    }
}
