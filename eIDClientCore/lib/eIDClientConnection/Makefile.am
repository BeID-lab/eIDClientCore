DEFS = eIDClientConnection.def
EXPORTS = eIDClientConnection.exports

EXTRA_DIST  = $(DEFS)

lib_LTLIBRARIES = libeIDClientConnection.la

noinst_HEADERS = eIDClientConnection.h

libeIDClientConnection_la_SOURCES = eIDClientConnection.c socket.c
libeIDClientConnection_la_LIBADD = $(LIBCURL) $(OPENSSL_LIBS)
libeIDClientConnection_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_LDFLAGS)
libeIDClientConnection_la_CPPFLAGS  = -I$(top_srcdir)/lib -DHAVE_CONFIG_H $(LIBCURL_CPPFLAGS)
libeIDClientConnection_la_DEPENDENCIES = 
if WIN32
libeIDClientConnection_la_LIBADD += -lws2_32
libeIDClientConnection_la_LDFLAGS += -export-symbols $(EXPORTS) -no-undefined
libeIDClientConnection_la_DEPENDENCIES += $(EXPORTS)
endif

$(EXPORTS): $(DEFS)
	cat $^ | grep -v LIBRARY | grep -v EXPORTS | grep eID > $@
