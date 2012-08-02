lib_LTLIBRARIES = libnPAClientECardLib.la

noinst_HEADERS = eIdClientCoreLib.h eIdECardClient.h eIdUtils.h ePAClientProtocol.h nPAClient.h

libnPAClientECardLib_la_SOURCES = eIdClientCoreLib.cpp eIdECardClient.cpp eIdUtils.cpp ePAClientProtocol.cpp nPAClient.cpp
# libeidasn1.la, libeCardCore.la are already included in libepa-api.la, so we skip them here
libnPAClientECardLib_la_LIBADD = $(EXPAT_LIBS) $(CRYPTOPP_LIBS) \
								 $(top_builddir)/lib/epa-api/libepa-api.la \
								 $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
								 $(top_builddir)/lib/eidasn1/libeidasn1.la \
								 $(top_builddir)/lib/eCardCore/libeCardCore.la
libnPAClientECardLib_la_CPPFLAGS = $(EXPAT_CFLAGS) $(CRYPTOPP_CFLAGS) \
								   -I$(top_srcdir)/lib \
								   -I$(top_srcdir)/lib/eCardCore \
								   -I$(top_srcdir)/lib/epa-api \
								   -I$(top_srcdir)/lib/eidasn1 \
								   -I$(top_srcdir)/lib/eIDClientConnection
