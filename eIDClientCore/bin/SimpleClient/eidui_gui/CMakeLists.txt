cmake_minimum_required(VERSION 3.0.2)

add_library(eidui_gui SHARED MainFrame.cpp eidui_gui.cpp ErrorMessages.cpp)

include_directories(.
${CMAKE_SOURCE_DIR}/lib 
${CMAKE_SOURCE_DIR}/lib/eIDClientCore
${wxWidgets_INCLUDE_DIRS})

message("wxWidgets_CXX_FLAGS: ${wxWidgets_CXX_FLAGS}, wxWidgets_DEFINITIONS: ${wxWidgets_DEFINITIONS}")
add_definitions(${wxWidgets_CXX_FLAGS})
target_compile_definitions(eidui_gui PRIVATE ${wxWidgets_DEFINITIONS})

#Private to prevent overlinking, see http://www.kaizou.org/2015/01/linux-libraries/
#and https://github.com/kaizouman/linux-shlib-link-samples/blob/master/CMakeLists.txt
message("wxWidgets_LIBRARIES: ${wxWidgets_LIBRARIES}")
target_link_libraries(eidui_gui PRIVATE ${wxWidgets_LIBRARIES})

install(TARGETS eidui_gui DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})