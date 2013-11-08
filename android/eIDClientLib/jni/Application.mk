##
# Copyright (C) 2013 Bundesdruckerei GmbH
##
APP_OPTIM := release
NDK_TOOLCHAIN_VERSION := 4.8
APP_ABI := armeabi
APP_CPPFLAGS += -fexceptions -frtti
APP_STL := stlport_shared
APP_MODULES :=stlport_shared eidclient-wrapper externalReader