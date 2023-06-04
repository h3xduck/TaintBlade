cmake_minimum_required(VERSION 3.5)

project(PinTracerUI VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Sql REQUIRED)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        Globals.h
        Globals.cpp
        ExecutionBridge.h
        ExecutionBridge.cpp
        PinConfigurationDialog.h
        PinConfigurationDialog.cpp
        DatabaseManager.h
        DatabaseManager.cpp
        TracedProcessWidget.h
        TracedProcessWidget.cpp
        MultiWindowViewWidget.h
        MultiWindowViewWidget.cpp
        TracedProcessDrawer.h
        TracedProcessDrawer.cpp
)

set(UI_HEADERS
    mainwindow.ui
    PinConfigurationDialog.ui
    TracedProcessWidget.ui
    MultiWindowViewWidget.ui
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(PinTracerUI
        MainToolBarResource.qrc
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        ${UI_HEADERS}
    )
endif()

target_link_libraries(PinTracerUI PRIVATE Qt${QT_VERSION_MAJOR}::Widgets PRIVATE Qt::Sql)

set_target_properties(PinTracerUI PROPERTIES
    WIN32_EXECUTABLE TRUE
)

install(TARGETS PinTracerUI
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(PinTracerUI)
endif()
