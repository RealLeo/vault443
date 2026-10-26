cmake_minimum_required(VERSION 3.21)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VAULT443_VERSION LIMIT_COUNT 1)
project(vault443 VERSION ${VAULT443_VERSION} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets Quick QuickControls2 DBus)
qt_add_executable(vault443
    ui/main.cpp ui/bridge.cpp ui/bridge.h ui/tray.cpp ui/tray.h ui/language.cpp ui/language.h)
target_compile_definitions(vault443 PRIVATE VAULT443_APP_VERSION="${PROJECT_VERSION}")
target_link_libraries(vault443 PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Quick Qt6::QuickControls2 Qt6::DBus)
add_library(vault443-ui-resources OBJECT)
target_link_libraries(vault443-ui-resources PRIVATE Qt6::Core)
# lrelease runs on the build host even when the application targets ARM64.
# Do not discover an executable under the target sysroot.
find_program(VAULT443_LRELEASE NAMES lrelease lrelease6
    HINTS "${QT_HOST_PATH}/lib/qt6/bin" "${CMAKE_SOURCE_DIR}/.cache/qt/usr/lib/qt6/bin" /usr/lib/qt6/bin
    NO_CMAKE_FIND_ROOT_PATH REQUIRED)
set(VAULT443_RUSSIAN_QM "${CMAKE_CURRENT_BINARY_DIR}/vault443_ru.qm")
add_custom_command(OUTPUT "${VAULT443_RUSSIAN_QM}"
    COMMAND "${VAULT443_LRELEASE}" "${CMAKE_CURRENT_SOURCE_DIR}/ui/i18n/vault443_ru.ts"
        -qm "${VAULT443_RUSSIAN_QM}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ui/i18n/vault443_ru.ts"
    VERBATIM)
set_source_files_properties("${VAULT443_RUSSIAN_QM}" PROPERTIES GENERATED TRUE QT_RESOURCE_ALIAS "vault443_ru.qm")
qt_add_resources(vault443-ui-resources "translations" PREFIX "/i18n" FILES "${VAULT443_RUSSIAN_QM}")
qt_add_resources(vault443-ui-resources "qml" PREFIX "/qml" BASE "ui/qml"
    FILES ui/qml/TrafficValue.qml ui/qml/TerminalToolTip.qml ui/qml/PointerHover.qml ui/qml/Main.qml ui/qml/MetalButton.qml ui/qml/TerminalDialog.qml ui/qml/TerminalField.qml
    ui/qml/ProfileIcon.qml ui/qml/IconPicker.qml ui/qml/TerminalCombo.qml ui/qml/TerminalTabButton.qml ui/qml/TerminalCheckBox.qml)
# Explicit runtime assets: source artwork, manifests and licenses stay outside rcc.
qt_add_resources(vault443-ui-resources "skin" PREFIX "/assets" BASE "assets" FILES
    assets/skin/button-green.png
    assets/skin/button-red.png
    assets/skin/card-1.png
    assets/skin/card-2.png
    assets/skin/card-3.png
    assets/skin/checkbox-off.png
    assets/skin/checkbox-on.png
    assets/skin/emblem-antenna.png
    assets/skin/emblem-dish.png
    assets/skin/emblem-globe.png
    assets/skin/led-off.png
    assets/skin/led-on.png
    assets/skin/stats.png
    assets/skin/window.png
    assets/fonts/RobotoCondensed-Regular.ttf
    assets/fonts/IosevkaTerm-Medium.ttf
    assets/profile-icons/atom.png
    assets/profile-icons/battery.png
    assets/profile-icons/binoculars.png
    assets/profile-icons/blank.png
    assets/profile-icons/canteen.png
    assets/profile-icons/compass.png
    assets/profile-icons/crt-terminal.png
    assets/profile-icons/gas-mask.png
    assets/profile-icons/gear.png
    assets/profile-icons/key.png
    assets/profile-icons/lightning.png
    assets/profile-icons/plug.png
    assets/profile-icons/radar.png
    assets/profile-icons/radiation.png
    assets/profile-icons/robot.png
    assets/profile-icons/rocket.png
    assets/profile-icons/satellite.png
    assets/profile-icons/shield.png
    assets/profile-icons/vacuum-tube.png
    assets/profile-icons/vault-door.png
    assets/profile-icons/wrench.png
)
target_link_libraries(vault443 PRIVATE vault443-ui-resources)
option(VAULT443_BUILD_UI_TESTS "Build isolated offscreen UI interaction tests" ON)
if(VAULT443_BUILD_UI_TESTS)
    enable_testing()
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    qt_add_executable(vault443-ui-tests ui/ui_tests.cpp ui/bridge.cpp ui/bridge.h ui/tray.cpp ui/tray.h ui/language.cpp ui/language.h)
    target_compile_definitions(vault443-ui-tests PRIVATE VAULT443_APP_VERSION="${PROJECT_VERSION}")
    target_link_libraries(vault443-ui-tests PRIVATE vault443-ui-resources Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Quick Qt6::QuickControls2 Qt6::DBus Qt6::Test)
    foreach(VAULT443_TEST_LANGUAGE IN ITEMS en ru)
        add_test(NAME gui-interactions-${VAULT443_TEST_LANGUAGE} COMMAND vault443-ui-tests)
        set_tests_properties(gui-interactions-${VAULT443_TEST_LANGUAGE} PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software;LANGUAGE=${VAULT443_TEST_LANGUAGE}")
    endforeach()
endif()
install(TARGETS vault443 RUNTIME DESTINATION bin)
