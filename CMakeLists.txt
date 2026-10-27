cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)          # MSVC_RUNTIME_LIBRARY

project(WasysProcKiller CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The driver image is compiled into the exe by the resource script; make the
# script depend on it so the .res (and the exe) rebuild when the .sys changes.
set_source_files_properties(WasysDriverResource.rc PROPERTIES
    OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libwasys.sys")

add_executable(WasysProcKiller WIN32
    WasysProcKiller.cpp
    WasysDriverLoader.cpp
    WasysDriverResource.rc)

target_include_directories(WasysProcKiller PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(WasysProcKiller PRIVATE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)

target_link_libraries(WasysProcKiller PRIVATE
    user32 gdi32 comctl32 advapi32 bcrypt)

if (MSVC)
    target_compile_options(WasysProcKiller PRIVATE /W4 /EHsc)
    target_link_options(WasysProcKiller PRIVATE
        /SUBSYSTEM:WINDOWS,6.01
        /MANIFEST:EMBED
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
    set_property(TARGET WasysProcKiller PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
