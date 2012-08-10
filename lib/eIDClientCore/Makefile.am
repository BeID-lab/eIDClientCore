lib_LTLIBRARIES = libeIDClientCore.la

noinst_HEADERS = eIdClientCoreLib.h eIdECardClient.h eIdUtils.h ePAClientProtocol.h nPAClient.h

libeIDClientCore_la_SOURCES = eIdClientCoreLib.cpp eIdECardClient.cpp eIdUtils.cpp ePAClientProtocol.cpp nPAClient.cpp
libeIDClientCore_la_LIBADD = $(EXPAT_LIBS) $(CRYPTOPP_LIBS) \
							 $(top_builddir)/lib/eCardCore/libeCardCore.la \
							 $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
							 $(top_builddir)/lib/eidasn1/libeidasn1.la \
							 $(top_builddir)/lib/nPA-EAC/libnPA-EAC.la
libeIDClientCore_la_CPPFLAGS = $(EXPAT_CFLAGS) $(CRYPTOPP_CFLAGS) \
							   -I$(top_srcdir)/lib \
							   -I$(top_srcdir)/lib/eIDClientConnection \
							   -I$(top_srcdir)/lib/eidasn1
