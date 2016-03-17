cmake_minimum_required(VERSION 3.0.2)

add_library(eIDClientCore SHARED eIDClientCore.cpp eIDUtils.cpp eIDECardClientPAOS.cpp ../debug.c ../testing.c) 
include_directories(${CRYPTO++_INCLUDE_DIR}/.. ../ ../eIDClientConnection ${LIBEIDASN1_BINARY_DIR} ../eidasn1)

target_link_libraries(eIDClientCore ${EXPAT_LIBRARIES} ${CRYPTO++_LIBRARIES} eCardCore eIDClientConnection eidasn1 nPA-EAC)
install(TARGETS eIDClientCore DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})