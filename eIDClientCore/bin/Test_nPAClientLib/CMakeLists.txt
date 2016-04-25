cmake_minimum_required(VERSION 3.0.2)

install(PROGRAMS load_test.bash DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

if(GENGETOPT)
	add_custom_command(OUTPUT cmdline.c cmdline.h switch_file COMMAND gengetopt --include-getopt < ${CMAKE_CURRENT_SOURCE_DIR}/Start_Testcase.ggo && echo "new" > switch_file)
	set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES switch_file)
#	TODO:
#	clean-local:
#	touch Start_Testcase.ggo #Do not delete cmdline.c and cmdline.h, but trigger rebuild of these two files
endif()

include_directories(. 
${EXPAT_INCLUDE_DIRS} 
${CMAKE_SOURCE_DIR}/lib 
${CMAKE_SOURCE_DIR}/lib/eIDClientConnection 
${CMAKE_SOURCE_DIR}/lib/eIDClientCore)

set(TEST_NPACLIENTLIB_SOURCES Test_nPAClientLib.cpp eidui_cli.cpp)
add_library(Test_nPAClientLib SHARED ${TEST_NPACLIENTLIB_SOURCES})
target_link_libraries(Test_nPAClientLib ${EXPAT_LIBRARIES} eIDClientConnection eIDClientCore)

if(WIN32)
	target_link_libraries(Test_nPAClientLib -lws2_32 -lwininet)
else()
	target_link_libraries(Test_nPAClientLib ${CMAKE_THREAD_LIBS_INIT})
endif()

install(TARGETS Test_nPAClientLib DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})

add_executable(Start_Testcase Start_Testcase.cpp cmdline.c)
target_link_libraries(Start_Testcase Test_nPAClientLib eIDClientCore)
install(TARGETS Start_Testcase DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
add_definitions(-DPACKAGE="eidclientcore" -DVERSION="0.2")
