##
# Copyright (C) 2013 Bundesdruckerei GmbH
##
LOCAL_PATH	:= $(call my-dir)
##LIB_PATH relative to LOCAL_PATH
LIB_PATH        := ../../eIDClientCore-0.2_arm/lib
LIBEID_PATH	:= $(LOCAL_PATH)/../../../lib

#########################################################
### START DEPENDENCIES
#########################################################
#Crypto
include $(CLEAR_VARS)

LOCAL_MODULE	:= crypto-static
LOCAL_SRC_FILES := $(LIB_PATH)/libcrypto.a

include $(PREBUILT_STATIC_LIBRARY)
#############################################################
#SSL
include $(CLEAR_VARS)

LOCAL_MODULE 			:= ssl-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libssl.a
LOCAL_STATIC_LIBRARIES 	:= crypto-static

include $(PREBUILT_STATIC_LIBRARY)
#############################################################
#Curl
include $(CLEAR_VARS)

LOCAL_MODULE 			:= curl-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libcurl.a
LOCAL_STATIC_LIBRARIES 	:= ssl-static
LOCAL_LDLIBS			:= -lz

include $(PREBUILT_STATIC_LIBRARY)
#############################################################
#Expat
include $(CLEAR_VARS)

LOCAL_MODULE 			:= expat-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libexpat.a

include $(PREBUILT_STATIC_LIBRARY)

#############################################################
# eIDClientConnection
include $(CLEAR_VARS)

LOCAL_MODULE 			:= eIDClientConnection-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libeIDClientConnection.a

LOCAL_STATIC_LIBRARIES	:= curl-static

include $(PREBUILT_STATIC_LIBRARY)
#############################################################
#CryptoPP
include $(CLEAR_VARS)

LOCAL_MODULE 			:= cryptopp-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libcryptopp.a

include $(PREBUILT_STATIC_LIBRARY)
########################################################
# eIDClientCore
include $(CLEAR_VARS)

LOCAL_MODULE 			:= eIDClientCore-static
LOCAL_SRC_FILES 		:= $(LIB_PATH)/libeIDClientCore.a
LOCAL_STATIC_LIBRARIES 	:= cryptopp-static expat-static eIDClientConnection-static

include $(PREBUILT_STATIC_LIBRARY)
#########################################################
### END DEPENDENCIES
#########################################################


include $(CLEAR_VARS)

LOCAL_MODULE			:= eidclient-wrapper
LOCAL_SRC_FILES 		:= de_bdr_eidclient_EIdSession.cpp
LOCAL_C_INCLUDES 		:= $(LIBEID_PATH)
LOCAL_C_INCLUDES        += $(LOCAL_PATH)/../../reader/jni
LOCAL_LDLIBS			:= -lz -llog
LOCAL_STATIC_LIBRARIES 	:= eIDClientCore-static

include $(BUILD_SHARED_LIBRARY)

########################################################
# external Reader
READER_SHARED_LIBRARIES:= eidclient-wrapper
include $(LOCAL_PATH)/../../reader/jni/Android.mk
