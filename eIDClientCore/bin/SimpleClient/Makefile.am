bin_PROGRAMS = SimpleClient

noinst_HEADERS = CeIdObject.h CivetServer.h civetweb.h eidui_cli.h

SimpleClient_SOURCES  = main.cpp eidui_cli.cpp CeIdObject.cpp CivetServer.cpp civetweb.c
SimpleClient_CPPFLAGS = $(EXPAT_CFLAGS) \
                             -I$(top_srcdir)/lib \
                             -I$(top_srcdir)/lib/eIDClientConnection \
                             -I$(top_srcdir)/lib/eIDClientCore \
                             -I$(top_srcdir)/bin/SimpleClient/eidui_gui
SimpleClient_LDADD    = $(EXPAT_LIBS) \
                             $(top_builddir)/lib/eIDClientConnection/libeIDClientConnection.la \
                             $(top_builddir)/lib/eIDClientCore/libeIDClientCore.la \
                             $(top_builddir)/bin/SimpleClient/eidui_gui/libeidui_gui.la    
if WIN32
SimpleClient_LDADD   += -lws2_32 -lwininet
else
SimpleClient_CPPFLAGS+= $(PTHREAD_CFLAGS)
SimpleClient_LDADD   += $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
endif
