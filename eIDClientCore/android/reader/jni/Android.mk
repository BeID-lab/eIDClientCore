##
# Copyright (C) 2013 Bundesdruckerei GmbH
##

#YOU HAVE TO SET READER_SHARED_LIBRARIES
#	i.e SET READER_SHARED_LIBRARIES:= eidclient-wrapper
#
########################################################
LOCAL_PATH				:= $(call my-dir)
include $(CLEAR_VARS)

LIBEID_PATH				:= $(LOCAL_PATH)/../../../lib

LOCAL_MODULE			:= externalReader
LOCAL_SRC_FILES 		:= de_bdr_eidclient_external_reader.cpp
LOCAL_C_INCLUDES		:= $(LIBEID_PATH)
LOCAL_LDLIBS			:= -llog
LOCAL_SHARED_LIBRARIES 	:= $(READER_SHARED_LIBRARIES)

include $(BUILD_SHARED_LIBRARY)
