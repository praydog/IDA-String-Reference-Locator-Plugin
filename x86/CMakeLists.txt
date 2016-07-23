cmake_minimum_required(VERSION 3.1)

set(PROJECT_NAME IDA_StringRef_Locator)
set(CMAKE_CONFIGURATION_TYPES Release)

project(${PROJECT_NAME} CXX)

set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

file(GLOB_RECURSE SOURCES "../src/*.cpp")
file(GLOB_RECURSE HEADERS "../src/*.hpp")

include_directories("../src")

add_definitions(-D__IDP__)
add_library(${PROJECT_NAME} SHARED ${HEADERS} ${SOURCES})

if (WIN32)
	add_definitions(-D__NT__)
	target_link_libraries(${PROJECT_NAME} x86_win_vc_32/ida)
elseif (UNIX AND NOT APPLE)
	add_definitions(-D__LINUX__)
elseif (APPLE)
	add_definitions(-D__MAC__)
ENDIF()

set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".plw")