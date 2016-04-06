cmake_minimum_required(VERSION 3.0.2)

add_executable(SimpleClient main.cpp eidui_cli.cpp CeIdObject.cpp CivetServer.cpp civetweb.c)

include_directories(. 
${EXPAT_INCLUDE_DIRS} 
${CMAKE_SOURCE_DIR}/lib 
${CMAKE_SOURCE_DIR}/lib/eIDClientConnection 
${CMAKE_SOURCE_DIR}/lib/eIDClientCore
${CMAKE_CURRENT_SOURCE_DIR}/eidui_gui)

if(WIN32)
	target_link_libraries(SimpleClient -lws2_32 -lwininet)
else()
	target_link_libraries(SimpleClient ${CMAKE_THREAD_LIBS_INIT})
endif()

add_subdirectory(eidui_gui)

message("wxWidgets_LIBRARY_DIRS: ${wxWidgets_LIBRARY_DIRS}")
#set(INSTALL_RPATH_USE_LINK_PATH ${wxWidgets_LIBRARY_DIRS})
set_target_properties(SimpleClient PROPERTIES
	INSTALL_RPATH "${INSTALL_RPATH};${wxWidgets_LIBRARY_DIRS}"
	BUILD_WITH_INSTALL_RPATH TRUE)
target_link_libraries(SimpleClient ${EXPAT_LIBRARIES} ${LIBDL_LIBRARIES} eIDClientConnection eIDClientCore eidui_gui)
install(TARGETS SimpleClient DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
add_definitions(-DPACKAGE="eidclientcore" -DVERSION="0.2")