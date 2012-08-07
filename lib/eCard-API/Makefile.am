lib_LTLIBRARIES = libeCard-API.la

noinst_HEADERS = eIdClientCoreLib.h eIdECardClient.h eIdUtils.h ePAClientProtocol.h nPAClient.h

libeCard_API_la_SOURCES = eIdClientCoreLib.cpp eIdECardClient.cpp eIdUtils.cpp ePAClientProtocol.cpp nPAClient.cpp
# libeidasn1.la, libeCardCore.la are already included in libepa-api.la, so we skip them here
libeCard_API_la_LIBADD = $(EXPAT_LIBS) $(CRYPTOPP_LIBS) \
						 $(top_builddir)/lib/nPA-EAC/libnPA-EAC.la \
						 $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
						 $(top_builddir)/lib/eidasn1/libeidasn1.la \
						 $(top_builddir)/lib/eCardCore/libeCardCore.la
libeCard_API_la_CPPFLAGS = $(EXPAT_CFLAGS) $(CRYPTOPP_CFLAGS) \
						   -I$(top_srcdir)/lib \
						   -I$(top_srcdir)/lib/eCardCore \
						   -I$(top_srcdir)/lib/nPA-EAC \
						   -I$(top_srcdir)/lib/eidasn1 \
						   -I$(top_srcdir)/lib/eIDClientConnection
