lib_LTLIBRARIES = libTest_nPAClientLib.la
bin_PROGRAMS = Start_Testcase
dist_bin_SCRIPTS = load_test.bash

noinst_HEADERS = eidui_cli.h
include_HEADERS = Test_nPAClientLib.h

if HAS_GENGETOPT
BUILT_SOURCES = cmdline.c #cmdline.h is generated implicitly
cmdline.c: Start_Testcase.ggo
	gengetopt --include-getopt < Start_Testcase.ggo

clean-local:
	touch Start_Testcase.ggo #Do not delete cmdline.c and cmdline.h, but trigger rebuild of these two files
endif

libTest_nPAClientLib_la_SOURCES		= Test_nPAClientLib.cpp eidui_cli.cpp
libTest_nPAClientLib_la_CPPFLAGS	= $(EXPAT_CFLAGS) \
					-I$(top_srcdir)/lib \
					-I$(top_srcdir)/lib/eIDClientConnection \
					-I$(top_srcdir)/lib/eIDClientCore
libTest_nPAClientLib_la_LIBADD		= $(EXPAT_LIBS) \
					$(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
					$(top_builddir)/lib/eIDClientCore/libeIDClientCore.la

if WIN32
libTest_nPAClientLib_la_LIBADD		+= -lws2_32 -lwininet
else
libTest_nPAClientLib_la_CPPFLAGS	+= $(PTHREAD_CFLAGS)
libTest_nPAClientLib_la_LIBADD		+= $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
endif

Start_Testcase_SOURCES 	= Start_Testcase.cpp cmdline.c
Start_Testcase_CPPFLAGS	= -I$(top_srcdir)/lib
Start_Testcase_LDADD	= libTest_nPAClientLib.la \
			  $(top_builddir)/lib/eIDClientCore/libeIDClientCore.la
