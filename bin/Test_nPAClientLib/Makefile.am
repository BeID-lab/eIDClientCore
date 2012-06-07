bin_PROGRAMS = Test_nPAClientLib

INCLUDES = -I$(top_srcdir)/lib/nPAClientECardLib
LIBS = $(top_builddir)/lib/nPAClientECardLib/libnPAClientECardLib.la

Test_nPAClientLib_SOURCES = Test_nPAClientLib.cpp
Test_nPAClientLib_LDADD  = $(EXPAT_LIBS) \
						   $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la
if WIN32
Test_nPAClientLib_LDADD += -lws2_32 -lwininet
endif
Test_nPAClientLib_CPPFLAGS = $(EXPAT_CFLAGS) \
							 -I$(top_srcdir)/lib/eCardCore \
							 -I$(top_srcdir)/lib/eIDClientConnection
