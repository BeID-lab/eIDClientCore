noinst_LTLIBRARIES = libepa-api.la

noinst_HEADERS = ePAAPI.h  ePAAPI_internal.h  ePACard.h  ePACommon.h  ePAStatus.h

libepa_api_la_SOURCES = ePAAPI.cpp  ePA_CA.cpp  ePACard.cpp  ePACommon.cpp  ePA_PACE.cpp  ePA_TA.cpp
libepa_api_la_LIBADD = $(CRYPTOPP_LIBS) \
					   $(top_builddir)/lib/eidasn1/libeidasn1.la \
					   $(top_builddir)/lib/eCardCore/libeCardCore.la
libepa_api_la_CPPFLAGS = $(CRYPTOPP_CFLAGS) \
						 -I$(top_srcdir)/lib/eCardCore \
						 -I$(top_srcdir)/lib/eidasn1
