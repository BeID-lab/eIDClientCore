cmake_minimum_required(VERSION 3.0.2)

add_library(eIDClientConnection SHARED eIDClientConnection.c socket.c) 
include_directories(../ ${CURL_INCLUDE_DIRS})

#TODO: Check, if the test cases can also work without these two flags
add_definitions(-DSKIP_PEER_VERIFICATION -DSKIP_HOSTNAME_VERIFICATION)

target_link_libraries(eIDClientConnection ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})
install(TARGETS eIDClientConnection DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})