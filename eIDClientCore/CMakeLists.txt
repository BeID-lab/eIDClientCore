cmake_minimum_required(VERSION 3.0.2)

find_package(Git)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule init)
execute_process (COMMAND ${GIT_EXECUTABLE} submodule update)

include(GNUInstallDirs)
include(FindPkgConfig)
include(CheckIncludeFile)

set(ENV{PKG_CONFIG_PATH} "${BUILD_DIR}/lib/pkgconfig/:${BUILD_DIR}/lib64/pkgconfig/:$ENV{PKG_CONFIG_PATH}")

find_program(ASN1C asn1c)
find_program(GENGETOPT gengetopt)

# Do not use special C++11 settings when cross-compiling for android
if(NOT ANDROID)
  #Usable in cmake 3.1 and higher
  #set(CMAKE_CXX_STANDARD 11)
  #set(CMAKE_CXX_STANDARD_REQUIRED ON)
  #Also usable below cmake 3.1
  set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++11)
endif()

find_package(Crypto++ REQUIRED)
find_package(EXPAT REQUIRED)

find_package(Threads)

find_package(PCSC REQUIRED)
if(WIN32)
    if(NOT PCSC_LIBRARIES)
        set(PCSC_LIBRARIES -lwinscard)
    endif()
else()
    find_package(LibDL REQUIRED)
endif()

option(DISABLE_EXTERNAL "Define if External reader is disabled." OFF)
option(DISABLE_PCSC "Define if PC/SC readers are disabled." OFF)

CHECK_INCLUDE_FILE(eIDmfcUI.h EID_GUI_AVAILABLE)
if(NOT EID_GUI_AVAILABLE)
	add_definitions(-DDISABLE_EIDGUI)
endif()

find_package(CURL REQUIRED)
if(CURL_FOUND)
	add_definitions(-DHAVE_LIBCURL)
endif()
find_package(OpenSSL REQUIRED)

set(wxWidgets_CONFIG_OPTIONS --libs richtext)
find_package(wxWidgets 3.0.2 REQUIRED)

add_subdirectory(lib)
add_subdirectory(bin)