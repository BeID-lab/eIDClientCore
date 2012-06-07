DEFS = eIDClientConnection.def
EXPORTS = eIDClientConnection.exports

EXTRA_DIST  = $(DEFS) gnutls.c socket.c

lib_LTLIBRARIES = libeIDClientConnection.la

noinst_HEADERS = eIDClientConnection.h

libeIDClientConnection_la_SOURCES = eIDClientConnection.cpp
libeIDClientConnection_la_LIBADD = $(GNUTLS_LIBS)
if WIN32
libeIDClientConnection_la_LIBADD += -lws2_32
endif
libeIDClientConnection_la_LDFLAGS = $(AM_LDFLAGS) \
									-export-symbols $(EXPORTS) -no-undefined
libeIDClientConnection_la_CPPFLAGS = $(GNUTLS_CFLAGS)
libeIDClientConnection_la_DEPENDENCIES = $(EXPORTS)

$(EXPORTS): $(DEFS)
	cat $^ | grep -v LIBRARY | grep -v EXPORTS > $@


if BUILD_GNUTLS
PATCH ?= $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)


GNUTLS_VERSION = 2.10.2
GNUTLS_TAR_BZ2 = $(abs_builddir)/gnutls-$(GNUTLS_VERSION).tar.bz2
GNUTLS_DIR = $(abs_builddir)/gnutls-$(GNUTLS_VERSION)
GNUTLS = $(GNUTLS_DIR)/lib/.libs/libgnutls.a


$(GNUTLS_TAR_BZ2):
	$(WGET) ftp://ftp.gnu.org/gnu/gnutls/`basename $(GNUTLS_TAR_BZ2)`

$(GNUTLS_DIR)/configure.ac: $(GNUTLS_TAR_BZ2)
	tar xjf $(GNUTLS_TAR_BZ2)
	touch $(GNUTLS_DIR)/configure.ac

$(GNUTLS_DIR)/lib/auth_rsa_psk.c: $(GNUTLS_DIR)/configure.ac
	echo $(GNUTLS_DIR)/lib/auth_rsa_psk.c $(GNUTLS)
	$(PATCH) -d $(GNUTLS_DIR) -p1 < $(srcdir)/gnutls-2.10.2_add_rsa_psk.patch

$(GNUTLS): $(GNUTLS_DIR)/lib/auth_rsa_psk.c
	cd $(GNUTLS_DIR)/lib && $(AUTORECONF)
	cd $(GNUTLS_DIR)/lib && ./configure --enable-static --with-pic
	$(MAKE) -C $(GNUTLS_DIR)/lib

# building libgnutls also generates gnutls/gnutls.h
eIDClientConnection.cpp: $(GNUTLS)

libeIDClientConnection_la_LIBADD += $(GNUTLS) -lgcrypt
libeIDClientConnection_la_CPPFLAGS += -I$(GNUTLS_DIR)/lib/includes -I$(GNUTLS_DIR)/libextra/includes
libeIDClientConnection_la_DEPENDENCIES += $(GNUTLS)

#install-exec-local:
#$(MAKE) -C $(GNUTLS_DIR)/lib install
endif
