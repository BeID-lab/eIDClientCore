noinst_LTLIBRARIES = libepa-api.la

noinst_HEADERS = ePAAPI.h  ePACard.h  ePACommon.h  ePAStatus.h

libepa_api_la_SOURCES = ePAAPI.cpp  ePA_CA.cpp  ePACard.cpp  ePACommon.cpp  ePA_PACE.cpp  ePA_TA.cpp
libepa_api_la_LIBADD = $(CRYPTOPP_LIBS)
libepa_api_la_CPPFLAGS = $(CRYPTOPP_CFLAGS) \
						 -I$(top_srcdir)/lib/eCardCore \
						 -I$(top_srcdir)/lib \
						 -I$(top_srcdir)/lib/eidasn1
