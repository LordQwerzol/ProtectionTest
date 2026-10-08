cmake_minimum_required(VERSION 3.19)
project(ProtectionTest LANGUAGES CXX)

set(APP_ICON_RC "${CMAKE_CURRENT_SOURCE_DIR}/resources/app_icon.rc")

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)

qt_standard_project_setup()
include(GNUInstallDirs)

qt_add_resources(APP_RESOURCES resources.qrc)

qt_add_executable(ProtectionTest
    WIN32 MACOSX_BUNDLE
    src/main.cpp
    src/mainwindow.cpp
    src/mainslots.cpp
    include/mainwindow.h
    ui/mainwindow.ui
    ${APP_RESOURCES}
    ${APP_ICON_RC}
)

target_include_directories(ProtectionTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(ProtectionTest PROPERTIES
    AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui
)

target_link_libraries(ProtectionTest
    PRIVATE
        Qt::Core
        Qt::Widgets
        Qt6::Network
)

if(MSVC)
    target_compile_options(ProtectionTest PRIVATE /utf-8)
endif()

install(TARGETS ProtectionTest
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET ProtectionTest
    OUTPUT_SCRIPT deploy_script
    DEPLOY_TOOL_OPTIONS --no-quick-import
    NO_UNSUPPORTED_PLATFORM_ERROR
)

install(SCRIPT ${deploy_script})


