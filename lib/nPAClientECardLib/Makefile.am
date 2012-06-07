lib_LTLIBRARIES = libnPAClientECardLib.la

noinst_HEADERS = eIdClientCoreLib.h eIdECardClient.h eIdUtils.h ePAClientProtocol.h nPAClient.h

libnPAClientECardLib_la_SOURCES = eIdClientCoreLib.cpp eIdECardClient.cpp eIdUtils.cpp ePAClientProtocol.cpp nPAClient.cpp
# libeidasn1.la and libeCardCore.la are already included in libepa-api.la, so we skip them here
libnPAClientECardLib_la_LIBADD = $(EXPAT_LIBS) $(CRYPTOPP_LIBS) \
								 $(top_builddir)/lib/epa-api/libepa-api.la \
								 $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la
#libnPAClientECardLib_la_LDFLAGS = $(AM_LDFLAGS) \
								  #$(top_builddir)/lib/eCardCore/libeCardCore.la \
								  #$(top_builddir)/lib/epa-api/libepa-api.la \
								  #$(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la
libnPAClientECardLib_la_CPPFLAGS = $(EXPAT_CFLAGS) $(CRYPTOPP_CFLAGS) \
								   -I$(top_srcdir)/lib/eCardCore \
								   -I$(top_srcdir)/lib/epa-api \
								   -I$(top_srcdir)/lib/eidasn1 \
								   -I$(top_srcdir)/lib/eIDClientConnection
