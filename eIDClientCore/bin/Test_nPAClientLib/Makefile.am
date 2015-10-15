bin_PROGRAMS = Test_nPAClientLib_noSaml Test_nPAClientLib_Saml_1 Test_nPAClientLib_Saml_2 Test_nPAClientLib_Selbstauskunft_Wuerzburg Test_nPAClientLib_AutentApp
lib_LTLIBRARIES = libTest_nPAClientLib_AutentApp.la

noinst_HEADERS = eidui_cli.h
include_HEADERS = Test_nPAClientLib.h

Test_nPAClientLib_SOURCES  = Test_nPAClientLib.cpp eidui_cli.cpp
Test_nPAClientLib_CPPFLAGS = $(EXPAT_CFLAGS) \
                             -I$(top_srcdir)/lib \
                             -I$(top_srcdir)/lib/eIDClientConnection \
                             -I$(top_srcdir)/lib/eIDClientCore
Test_nPAClientLib_LDADD    = $(EXPAT_LIBS) \
                             $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
                             $(top_builddir)/lib/eIDClientCore/libeIDClientCore.la
if WIN32
Test_nPAClientLib_LDADD   += -lws2_32 -lwininet
else
Test_nPAClientLib_CPPFLAGS+= $(PTHREAD_CFLAGS)
Test_nPAClientLib_LDADD   += $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
endif


Test_nPAClientLib_noSaml_SOURCES  = $(Test_nPAClientLib_SOURCES)
Test_nPAClientLib_noSaml_CPPFLAGS = $(Test_nPAClientLib_CPPFLAGS) -DSAML_VERSION_NO_SAML
Test_nPAClientLib_noSaml_LDADD    = $(Test_nPAClientLib_LDADD)

Test_nPAClientLib_Saml_1_SOURCES  = $(Test_nPAClientLib_SOURCES)
Test_nPAClientLib_Saml_1_CPPFLAGS = $(Test_nPAClientLib_CPPFLAGS) -DSAML_VERSION_SAML_1
Test_nPAClientLib_Saml_1_LDADD    = $(Test_nPAClientLib_LDADD)

Test_nPAClientLib_Saml_2_SOURCES  = $(Test_nPAClientLib_SOURCES)
Test_nPAClientLib_Saml_2_CPPFLAGS = $(Test_nPAClientLib_CPPFLAGS) -DSAML_VERSION_SAML_2
Test_nPAClientLib_Saml_2_LDADD    = $(Test_nPAClientLib_LDADD)

Test_nPAClientLib_Selbstauskunft_Wuerzburg_SOURCES  = $(Test_nPAClientLib_SOURCES)
Test_nPAClientLib_Selbstauskunft_Wuerzburg_CPPFLAGS = $(Test_nPAClientLib_CPPFLAGS) -DSELBSTAUSKUNFT_WUERZBURG
Test_nPAClientLib_Selbstauskunft_Wuerzburg_LDADD    = $(Test_nPAClientLib_LDADD)

Test_nPAClientLib_AutentApp_SOURCES  = $(Test_nPAClientLib_SOURCES)
Test_nPAClientLib_AutentApp_CPPFLAGS = $(Test_nPAClientLib_CPPFLAGS) -DAUTENTAPP
Test_nPAClientLib_AutentApp_LDADD    = $(Test_nPAClientLib_LDADD)

libTest_nPAClientLib_AutentApp_la_SOURCES  = $(Test_nPAClientLib_AutentApp_SOURCES)
libTest_nPAClientLib_AutentApp_la_CPPFLAGS = $(Test_nPAClientLib_AutentApp_CPPFLAGS) -DAS_LIBRARY
libTest_nPAClientLib_AutentApp_la_LIBADD    = $(Test_nPAClientLib_AutentApp_LDADD)
