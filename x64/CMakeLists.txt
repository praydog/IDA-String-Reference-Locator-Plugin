cmake_minimum_required(VERSION 3.1)

set(PROJECT_NAME64 IDA_StringRef_Locator64)
set(CMAKE_CONFIGURATION_TYPES Release)

project(${PROJECT_NAME64} CXX)

set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

file(GLOB_RECURSE SOURCES "../src/*.cpp")
file(GLOB_RECURSE HEADERS "../src/*.hpp")

LINK_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/bin)

include_directories("../src")

add_definitions(-D__EA64__ -D__IDP__ -D__X64__)
add_library(${PROJECT_NAME64} SHARED ${HEADERS} ${SOURCES})

if (WIN32)
	add_definitions(-D__NT__)
	target_link_libraries(${PROJECT_NAME64} x86_win_vc_64/ida)
elseif (UNIX AND NOT APPLE)
	add_definitions(-D__LINUX__)
elseif (APPLE)
	add_definitions(-D__MAC__)
ENDIF()

set_target_properties(${PROJECT_NAME64} PROPERTIES SUFFIX ".p64")
target_link_options(${PROJECT_NAME64} PUBLIC /EXPORT:PLUGIN)