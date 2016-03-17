cmake_minimum_required(VERSION 3.0.2)

set(LIBECARDCORE_SOURCES ICard.cpp CardCommand.cpp IReader.cpp)


if(NOT DISABLE_EXTERNAL)
	set (LIBECARDCORE_SOURCES ${LIBECARDCORE_SOURCES} ExternalReader.cpp)
endif()

if(NOT DISABLE_PCSC)
	set(LIBECARDCORE_SOURCES ${LIBECARDCORE_SOURCES} PCSCManager.cpp  PCSCReader.cpp pace_reader.cpp)
endif()

add_library(eCardCore SHARED ${LIBECARDCORE_SOURCES})
include_directories(../ ${PCSC_INCLUDE_DIRS})

if(NOT DISABLE_PCSC)
	if(PCSC_LIBRARIES)
		target_link_libraries(eCardCore ${PCSC_LIBRARIES})
	endif()
endif()

install(TARGETS eCardCore DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})