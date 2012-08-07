noinst_LTLIBRARIES = libnPA-EAC.la

noinst_HEADERS = nPAAPI.h  nPACard.h  nPACommon.h  nPAStatus.h

libnPA_EAC_la_SOURCES = nPAAPI.cpp  nPA_CA.cpp  nPACard.cpp  nPACommon.cpp  nPA_PACE.cpp  nPA_TA.cpp
libnPA_EAC_la_LIBADD = $(CRYPTOPP_LIBS)
libnPA_EAC_la_CPPFLAGS = $(CRYPTOPP_CFLAGS) \
						 -I$(top_srcdir)/lib/eCardCore \
						 -I$(top_srcdir)/lib \
						 -I$(top_srcdir)/lib/eidasn1
