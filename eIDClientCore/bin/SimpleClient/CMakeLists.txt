cmake_minimum_required(VERSION 3.0.2)

add_executable(SimpleClient main.cpp eidui_cli.cpp CeIdObject.cpp CivetServer.cpp civetweb.c)

include_directories(. 
${EXPAT_INCLUDE_DIRS} 
${CMAKE_SOURCE_DIR}/lib 
${CMAKE_SOURCE_DIR}/lib/eIDClientConnection 
${CMAKE_SOURCE_DIR}/lib/eIDClientCore)

if(WIN32)
	target_link_libraries(SimpleClient -lws2_32 -lwininet)
else()
	target_link_libraries(SimpleClient ${CMAKE_THREAD_LIBS_INIT})
endif()

target_link_libraries(SimpleClient ${EXPAT_LIBRARIES} ${LIBDL_LIBRARIES} eIDClientConnection eIDClientCore)
install(TARGETS SimpleClient DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
add_definitions(-DPACKAGE="eidclientcore" -DVERSION="0.2")