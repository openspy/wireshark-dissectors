cmake_minimum_required (VERSION 2.6)

project(gamespy_dissectors)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

file (GLOB MAIN_SRCS "*.c" "*.cpp")
file (GLOB MAIN_HDRS "*.h")

set (ALL_SRCS ${MAIN_SRCS} ${MAIN_HDRS})

# include_directories (${CMAKE_CURRENT_SOURCE_DIR} /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include /usr/include/wireshark)
include_directories (${CMAKE_CURRENT_SOURCE_DIR} C:\code\wireshark-win64-libs\vcpkg-export-20220726-1-win64ws\installed\x64-windows\lib\glib-2.0\include C:\code\extern\include C:\code\wireshark\include C:\code\wireshark C:\code\wireshark-win64-libs\vcpkg-export-20220726-1-win64ws\installed\x64-windows\include\glib-2.0)

source_group("Sources" FILES ${MAIN_SRCS})
source_group("Headers" FILES ${MAIN_HDRS})

add_library (gamespy_dissectors SHARED ${ALL_SRCS})
target_link_libraries(gamespy_dissectors wireshark)