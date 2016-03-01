cmake_minimum_required(VERSION 3.0.2)

include_directories(${CRYPTO++_INCLUDE_DIR}/.. ../ ../eidasn1)
include_directories(${LIBEIDASN1_BINARY_DIR})

set(NPA-EAC_SOURCES nPA_CA.cpp nPACard.cpp nPACommon.cpp nPA_PACE.cpp nPA_TA.cpp)
add_library(nPA-EAC SHARED ${NPA-EAC_SOURCES})

if(CRYPTO++_LIBRARIES)
	target_link_libraries(nPA-EAC ${CRYPTO++_LIBRARIES})
endif()

install(TARGETS nPA-EAC DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})