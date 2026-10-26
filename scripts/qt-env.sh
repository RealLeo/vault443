#!/bin/sh
# Source from the project root after bootstrap-qt.py, or use system Qt normally.
VAULT443_QT_PREFIX="$(pwd)/.cache/qt/usr"
if [ -d "$VAULT443_QT_PREFIX" ]; then
  export PATH="$VAULT443_QT_PREFIX/bin:$PATH"
  export LD_LIBRARY_PATH="$VAULT443_QT_PREFIX/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export QT_PLUGIN_PATH="$VAULT443_QT_PREFIX/lib/x86_64-linux-gnu/qt6/plugins"
  export QML2_IMPORT_PATH="$VAULT443_QT_PREFIX/lib/x86_64-linux-gnu/qt6/qml"
  export QML_IMPORT_PATH="$QML2_IMPORT_PATH"
  export CMAKE_PREFIX_PATH="$VAULT443_QT_PREFIX${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
fi
