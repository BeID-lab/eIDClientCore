cmake_minimum_required(VERSION 3.0.2)

add_subdirectory(eIDClientConnection)
add_subdirectory(eCardCore)
add_subdirectory(eidasn1)
get_directory_property(LIBEIDASN1_BINARY_DIR DIRECTORY eidasn1 DEFINITION LIBEIDASN1_BINARY_DIR)
add_subdirectory(nPA-EAC)
add_subdirectory(eIDClientCore) 