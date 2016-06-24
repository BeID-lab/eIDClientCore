cmake_minimum_required(VERSION 3.0.2)
project(eIDClientCore)

option(RebuildOpenSSL "Rebuild OpenSSL" ON)

include(ExternalProject)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-Modules)
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_PREFIX_PATH ${CMAKE_SOURCE_DIR}/build)

ExternalProject_Add(libcryptopp
	GIT_REPOSITORY https://github.com/weidai11/cryptopp
	PREFIX ${BUILD_DIR}
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
)

#ASN1C does not use cmake
set(ASN1C_DOWNLOAD_DIR ${BUILD_DIR}/src/asn1c)
ExternalProject_Add(asn1c
	URL https://lionet.info/soft/asn1c-0.9.24.tar.gz
	PREFIX ${BUILD_DIR}
	CONFIGURE_COMMAND ${ASN1C_DOWNLOAD_DIR}/configure --prefix=${BUILD_DIR}
	BUILD_IN_SOURCE 1
	BUILD_COMMAND make -C ${ASN1C_DOWNLOAD_DIR}
	INSTALL_COMMAND make -C ${ASN1C_DOWNLOAD_DIR} install
)

ExternalProject_Add(libexpat
	URL http://sourceforge.net/projects/expat/files/expat/2.1.0/expat-2.1.0.tar.gz
	URL_HASH SHA1=b08197d146930a5543a7b99e871cba3da614f6f0
	PREFIX ${BUILD_DIR}
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
)

#OpenSSL does not use cmake
set(OPENSSL_DOWNLOAD_DIR ${BUILD_DIR}/src/openssl)
if(RebuildOpenSSL)
	set(OPENSSL_BUILD_COMMAND make -C ${OPENSSL_DOWNLOAD_DIR} depend && )
	message("RebuildOpenSSL switched on. To disable, use cmake -DRebuildOpenSSL=OFF")
else()
	message("RebuildOpenSSL switched off. To enable, use cmake -DRebuildOpenSSL=ON")
endif()
set(OPENSSL_BUILD_COMMAND ${OPENSSL_BUILD_COMMAND} make -C ${OPENSSL_DOWNLOAD_DIR})
ExternalProject_Add(openssl
	GIT_REPOSITORY https://github.com/misery/openssl
	PREFIX ${BUILD_DIR}
	CONFIGURE_COMMAND ${OPENSSL_DOWNLOAD_DIR}/config --prefix=${BUILD_DIR} shared
	BUILD_IN_SOURCE 1
	BUILD_COMMAND ${OPENSSL_BUILD_COMMAND}
	INSTALL_COMMAND make -C ${OPENSSL_DOWNLOAD_DIR} install_sw
	TEST_AFTER_INSTALL 1
	TEST_COMMAND ${BUILD_DIR}/bin/openssl ciphers -v | grep RSAPSK
)

ExternalProject_Add(libcurl
	URL https://github.com/bagder/curl/releases/download/curl-7_44_0/curl-7.44.0.tar.gz
	PREFIX ${BUILD_DIR}
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}
)
add_dependencies(libcurl openssl)

ExternalProject_Add(eIDClientCore
	DOWNLOAD_COMMAND ""
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/eIDClientCore
	PREFIX ${BUILD_DIR}
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH} -DCMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}
)
add_dependencies(eIDClientCore libcryptopp asn1c libexpat openssl libcurl)
