DEFS = eIDClientConnection.def
EXPORTS = eIDClientConnection.exports

EXTRA_DIST  = $(DEFS) gnutls-2.10.2_add_rsa_psk.patch

lib_LTLIBRARIES = libeIDClientConnection.la

noinst_HEADERS = eIDClientConnection.h

libeIDClientConnection_la_SOURCES = eIDClientConnection.c gnutls.c socket.c
libeIDClientConnection_la_LIBADD = $(GNUTLS_LIBS)
if WIN32
libeIDClientConnection_la_LIBADD += -lws2_32
endif
libeIDClientConnection_la_LDFLAGS = $(AM_LDFLAGS) \
									-export-symbols $(EXPORTS) -no-undefined
libeIDClientConnection_la_CFLAGS = $(GNUTLS_CFLAGS)
libeIDClientConnection_la_DEPENDENCIES = $(EXPORTS)

$(EXPORTS): $(DEFS)
	cat $^ | grep -v LIBRARY | grep -v EXPORTS | grep eID > $@


if BUILD_GNUTLS
PATCH ?= $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)


GNUTLS_VERSION = 2.10.2
GNUTLS_TAR_BZ2 = $(abs_builddir)/gnutls-$(GNUTLS_VERSION).tar.bz2
GNUTLS_DIR = $(abs_builddir)/gnutls-$(GNUTLS_VERSION)
GNUTLS_LIB_DIR = $(GNUTLS_DIR)/lib
GNUTLS = $(GNUTLS_LIB_DIR)/.libs/libgnutls.a


$(GNUTLS_TAR_BZ2):
	$(WGET) ftp://ftp.gnu.org/gnu/gnutls/`basename $(GNUTLS_TAR_BZ2)`

$(GNUTLS_LIB_DIR)/configure.ac: $(GNUTLS_TAR_BZ2)
	tar xjf $(GNUTLS_TAR_BZ2)
	touch $(GNUTLS_LIB_DIR)/configure.ac

$(GNUTLS_LIB_DIR)/auth_rsa_psk.c: $(GNUTLS_LIB_DIR)/configure.ac
	$(PATCH) -d $(GNUTLS_DIR) -p1 < $(srcdir)/gnutls-2.10.2_add_rsa_psk.patch

$(GNUTLS): $(GNUTLS_LIB_DIR)/auth_rsa_psk.c
	cd $(GNUTLS_LIB_DIR) && ./configure --enable-static --with-pic --without-zlib --with-included-libtasn1
	$(MAKE) -C $(GNUTLS_LIB_DIR)

# building libgnutls also generates gnutls/gnutls.h
eIDClientConnection.c: $(GNUTLS)

libeIDClientConnection_la_LIBADD += $(GNUTLS) -lgcrypt
libeIDClientConnection_la_CFLAGS += -I$(GNUTLS_LIB_DIR)/includes -I$(GNUTLS_LIB_DIR)/includes
libeIDClientConnection_la_DEPENDENCIES += $(GNUTLS)

#install-exec-local:
#$(MAKE) -C $(GNUTLS_LIB_DIR) install
endif
