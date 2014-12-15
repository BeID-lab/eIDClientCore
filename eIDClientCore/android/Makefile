abs_builddir = $(shell pwd)

PACKAGE_TARNAME=eIDClientCore
PACKAGE_VERSION=0.2
ANDROID_ARCH ?= arm
ANDROID_API ?= android-19
ANDROID_TOOL ?= $(ANDROID_ARCH)-linux-androideabi
ANDROID_TOOL_DIR ?= $(abs_builddir)/ndk
ANDROID_TARGETDIR = $(abs_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_$(ANDROID_ARCH)
ANDROID_SDK_ROOT ?= /opt/adt-bundle-linux-x86-20130729/sdk
ANDROID_NDK_ROOT ?= /opt/android-ndk-r9
MAKE_STANDALONE_TOOLCHAIN = $(ANDROID_NDK_ROOT)/build/tools/make-standalone-toolchain.sh
CROSS_COMPILE = $(ANDROID_TOOL)-

EXPAT_VERSION = 2.1.0
EXPAT = expat-$(EXPAT_VERSION)
EXPAT_DIR = $(abs_builddir)/$(EXPAT)
LIBEXPAT = $(ANDROID_TARGETDIR)/lib/libexpat.so
EXPAT_CONFIGURE = $(EXPAT_DIR)/configure

CURL = curl-7.32.0
CURL_DIR = $(abs_builddir)/$(CURL)
LIBCURL = $(ANDROID_TARGETDIR)/lib/libcurl.so
CURL_CONFIGURE = $(CURL_DIR)/configure

EIDCLIENTCORE_DIR = $(abs_builddir)/..
LIBEIDCLIENTCORE = $(ANDROID_TARGETDIR)/lib/libeIDClientCore.so

CRYPTOPP_DIR = $(abs_builddir)/cryptopp
LIBCRYPTOPP = $(ANDROID_TARGETDIR)/lib/libcryptopp.so
CRYPTOPP_MAKEFILE = $(CRYPTOPP_DIR)/GNUmakefile

CRYPTO = openssl-1.0.0k
CRYPTO_DIR = $(abs_builddir)/$(CRYPTO)
LIBCRYPTO = $(ANDROID_TARGETDIR)/lib/libcrypto.so
CRYPTO_MAKEFILE = $(CRYPTO_DIR)/Makefile

EIDCLIENT = $(abs_builddir)/eIDClientLib
EIDCLIENT_JAR = $(abs_builddir)/eIDClientLib/bin/classes.jar

all: 
	test -e .dependencies_built && $(MAKE) rebuild || true
	test -e .dependencies_built || $(MAKE) $(EIDCLIENT_JAR)

$(EXPAT_CONFIGURE):
	wget http://sourceforge.net/projects/expat/files/expat/$(EXPAT_VERSION)/$(EXPAT).tar.gz
	tar xvzf $(EXPAT_DIR).tar.gz
	touch $(EXPAT_CONFIGURE)

$(LIBEXPAT): $(EXPAT_CONFIGURE)
	$(MAKE) cross builddir=$(EXPAT_DIR)

$(CURL_CONFIGURE):
	wget http://curl.haxx.se/download/$(CURL).tar.bz2
	tar xvjf $(CURL_DIR).tar.bz2
	rm -f $(CURL_DIR)/Makefile
	touch $(CURL_CONFIGURE)

$(LIBCURL): $(CURL_CONFIGURE) $(LIBCRYPTO)
	$(MAKE) cross builddir=$(CURL_DIR)

$(CRYPTO_MAKEFILE):
	wget http://www.openssl.org/source/$(CRYPTO).tar.gz
	tar xvzf $(CRYPTO_DIR).tar.gz
	wget http://blog.cj2s.de/openssl-1.0.0c.tls-rsa-psk.tar
	tar xf openssl-1.0.0c.tls-rsa-psk.tar
	patch -d $(CRYPTO_DIR) -p1 < openssl-1.0.0c.tls-rsa-psk.patch || true
	cd $(CRYPTO_DIR) \
		&& $(CRYPTO_DIR)/Configure no-asm shared --prefix="/" linux-generic32 -DL_ENDIAN --cross-compile-prefix=$(CROSS_COMPILE) \
			-I$(ANDROID_TOOL_DIR)/include -I$(ANDROID_TOOL_DIR)/sysroot/usr/include -I$(ANDROID_TARGETDIR)/include \
			-L$(ANDROID_TOOL_DIR)/lib -L$(ANDROID_TOOL_DIR)/sysroot/usr/lib -L$(ANDROID_TARGETDIR)/lib
	touch $(CRYPTO_MAKEFILE)

$(LIBCRYPTO): $(CRYPTO_MAKEFILE)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(CRYPTO_DIR)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(CRYPTO_DIR) install_sw INSTALL_PREFIX=$(ANDROID_TARGETDIR)

$(CRYPTOPP_MAKEFILE):
	svn checkout https://svn.code.sf.net/p/cryptopp/code/trunk/c5 $(CRYPTOPP_DIR)
	patch -d $(CRYPTOPP_DIR) -p0 < GNUmakefile-android.patch
	touch $(CRYPTOPP_MAKEFILE)

$(LIBCRYPTOPP): $(CRYPTOPP_MAKEFILE)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(CRYPTOPP_DIR) PREFIX=$(ANDROID_TARGETDIR) \
			IS_ANDROID=1 ANDROID_STL_INC=$(ANDROID_TOOL_DIR)/include/g++ dynamic static install

$(LIBEIDCLIENTCORE):
	$(MAKE) $(LIBEXPAT) && $(MAKE) $(LIBCURL) && $(MAKE) $(LIBCRYPTOPP) && touch .dependencies_built
	$(MAKE) crosscommand
			
crosscommand:
	$(MAKE) cross builddir=$(EIDCLIENTCORE_DIR) EXTRA_OPTS="--enable-reader-external CRYPTOPP_LIBS=-lcryptopp CFLAGS='-D_EMULATE_TIMEGM'" \
		|| env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
			$(MAKE) -C $(EIDCLIENTCORE_DIR)/lib install DESTDIR=$(ANDROID_TARGETDIR)
	
android_stuff:
	$(ANDROID_SDK_ROOT)/tools/android update lib-project -p $(EIDCLIENT) --target $(ANDROID_API)
	$(ANDROID_NDK_ROOT)/ndk-build -C $(EIDCLIENT)
	cd $(EIDCLIENT) && ant release
	
rebuild: crosscommand android_stuff

clean:
	rm -rf $(ANDROID_TARGETDIR)
	rm -rf ndk
	rm -f LICENSE.txt README.openssl-1.0.0c openssl-1.0.0c.tls-rsa-psk.patch openssl-1.0.0c.tls-rsa-psk.tar
	rm -rf $(CRYPTOPP_DIR)
	rm -rf $(EXPAT_DIR)*
	rm -rf $(CURL_DIR)*
	rm -rf $(CRYPTO_DIR)*
	make clean -C $(EIDCLIENTCORE_DIR) || true
	rm -f $(EIDCLIENTCORE_DIR)/Makefile
	rm -f $(EIDCLIENT_JAR)
	rm -f .dependencies_built

cross:
	test -d $(ANDROID_TOOL_DIR) \
		|| $(MAKE_STANDALONE_TOOLCHAIN) --install-dir=$(ANDROID_TOOL_DIR) --arch=$(ANDROID_ARCH) --platform=$(ANDROID_API) --stl=stlport --toolchain=arm-linux-androideabi-4.8
	test -x $(builddir)/configure \
		|| (cd $(builddir) && autoreconf -vis)
	test -r $(builddir)/Makefile \
		|| (cd $(builddir) \
			&& env ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
			./configure \
			--prefix=/ \
			--host=$(ANDROID_TOOL) --target=$(ANDROID_TOOL) \
			$(EXTRA_OPTS) \
			PKG_CONFIG_SYSROOT_DIR=$(ANDROID_TARGETDIR) \
			PKG_CONFIG_LIBDIR=$(ANDROID_TARGETDIR)/lib/pkgconfig \
			CPPFLAGS="-I$(ANDROID_TOOL_DIR)/include -I$(ANDROID_TOOL_DIR)/sysroot/usr/include -I$(ANDROID_TOOL_DIR)/include/gabi++/include -I$(ANDROID_TARGETDIR)/include" \
			CXXFLAGS="-I$(ANDROID_TOOL_DIR)/include/g++ -lstlport_shared" \
			LDFLAGS="-L$(ANDROID_TOOL_DIR)/lib -L$(ANDROID_TOOL_DIR)/sysroot/usr/lib -L$(ANDROID_TARGETDIR)/lib")
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(builddir)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(builddir) install DESTDIR=$(ANDROID_TARGETDIR)

$(EIDCLIENT_JAR): $(LIBEIDCLIENTCORE) android_stuff