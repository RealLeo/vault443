cmake_minimum_required(VERSION 3.21)
project(vault443-tray-host-tests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets DBus Test)
get_filename_component(VAULT443_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
qt_add_executable(vault443-tray-host-tests
    tray_host_tests.cpp
    "${VAULT443_ROOT}/ui/tray.cpp" "${VAULT443_ROOT}/ui/tray.h"
    "${VAULT443_ROOT}/ui/bridge.cpp" "${VAULT443_ROOT}/ui/bridge.h"
    "${VAULT443_ROOT}/ui/language.cpp" "${VAULT443_ROOT}/ui/language.h")
target_include_directories(vault443-tray-host-tests PRIVATE "${VAULT443_ROOT}/ui")
target_link_libraries(vault443-tray-host-tests PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::DBus Qt6::Test)
qt_add_resources(vault443-tray-host-tests "tray_icon" PREFIX "/assets" BASE "${VAULT443_ROOT}/assets"
    FILES "${VAULT443_ROOT}/assets/profile-icons/vault-door.png")
find_program(VAULT443_LRELEASE NAMES lrelease lrelease6
    HINTS "${QT_HOST_PATH}/lib/qt6/bin" "${VAULT443_ROOT}/.cache/qt/usr/lib/qt6/bin" /usr/lib/qt6/bin
    NO_CMAKE_FIND_ROOT_PATH REQUIRED)
set(VAULT443_RUSSIAN_QM "${CMAKE_CURRENT_BINARY_DIR}/vault443_ru.qm")
add_custom_command(OUTPUT "${VAULT443_RUSSIAN_QM}"
    COMMAND "${VAULT443_LRELEASE}" "${VAULT443_ROOT}/ui/i18n/vault443_ru.ts" -qm "${VAULT443_RUSSIAN_QM}"
    DEPENDS "${VAULT443_ROOT}/ui/i18n/vault443_ru.ts" VERBATIM)
set_source_files_properties("${VAULT443_RUSSIAN_QM}" PROPERTIES GENERATED TRUE QT_RESOURCE_ALIAS "vault443_ru.qm")
qt_add_resources(vault443-tray-host-tests "translations" PREFIX "/i18n" FILES "${VAULT443_RUSSIAN_QM}")
