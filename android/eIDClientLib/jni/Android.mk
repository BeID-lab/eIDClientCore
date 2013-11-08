##
# Copyright (C) 2013 Bundesdruckerei GmbH
##
LOCAL_PATH	:= $(call my-dir)
LIB_PATH        := ../../eIDClientCore-0.2_arm/lib
LIBEID_PATH	:= $(LOCAL_PATH)/../../../lib

## DEPENDENCIES
include $(LOCAL_PATH)/deps.mk

########################################################

include $(CLEAR_VARS)

LOCAL_MODULE	:= eidclient-wrapper
LOCAL_SRC_FILES := de_bdr_eidclient_EIdSession.cpp
LOCAL_C_INCLUDES += $(LIBEID_PATH)
LOCAL_LDLIBS	+= -lz -llog
LOCAL_STATIC_LIBRARIES += eIDClientCore-static

include $(BUILD_SHARED_LIBRARY)

########################################################
include $(CLEAR_VARS)

LOCAL_MODULE	:= externalReader
LOCAL_SRC_FILES := de_bdr_eidclient_external_reader.cpp
LOCAL_C_INCLUDES += $(LIBEID_PATH)
LOCAL_LDLIBS	+= -llog
LOCAL_SHARED_LIBRARIES += eidclient-wrapper

include $(BUILD_SHARED_LIBRARY)
