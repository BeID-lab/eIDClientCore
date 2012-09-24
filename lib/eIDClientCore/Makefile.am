lib_LTLIBRARIES = libeIDClientCore.la

noinst_HEADERS = eIDClientCore.h eIDECardClient.h eIDUtils.h nPAClientProtocol.h nPAClient.h

libeIDClientCore_la_SOURCES = eIDClientCore.cpp eIDECardClient.cpp eIDUtils.cpp nPAClientProtocol.cpp nPAClient.cpp
libeIDClientCore_la_LIBADD = $(EXPAT_LIBS) $(CRYPTOPP_LIBS) \
							 $(top_builddir)/lib/eCardCore/libeCardCore.la \
							 $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
							 $(top_builddir)/lib/eidasn1/libeidasn1.la \
							 $(top_builddir)/lib/nPA-EAC/libnPA-EAC.la
libeIDClientCore_la_CPPFLAGS = $(EXPAT_CFLAGS) $(CRYPTOPP_CFLAGS) \
							   -I$(top_srcdir)/lib \
							   -I$(top_srcdir)/lib/eIDClientConnection \
							   -I$(top_srcdir)/lib/eidasn1
