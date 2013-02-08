bin_PROGRAMS = Test_nPAClientLib

noinst_HEADERS = url.h

Test_nPAClientLib_SOURCES = Test_nPAClientLib.cpp
Test_nPAClientLib_CXXFLAGS = $(EXPAT_CFLAGS) \
							 -I$(top_srcdir)/lib/eIDClientConnection \
							 -I$(top_srcdir)/lib/eIDClientCore
Test_nPAClientLib_LDADD  = $(EXPAT_LIBS) \
						   $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
						   $(top_builddir)/lib/eIDClientCore/libeIDClientCore.la
if WIN32
Test_nPAClientLib_LDADD += -lws2_32 -lwininet
else
Test_nPAClientLib_CXXFLAGS += -pthread
Test_nPAClientLib_LDADD  += -lpthread
endif
