abs_builddir = $(shell pwd)

SHELL=/bin/bash

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

CURL = curl-7.44.0
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
	echo "b08197d146930a5543a7b99e871cba3da614f6f0  expat-2.1.0.tar.gz" | sha1sum -c -
	tar xzf $(EXPAT_DIR).tar.gz
	touch $(EXPAT_CONFIGURE)

$(LIBEXPAT): $(EXPAT_CONFIGURE)
	$(MAKE) cross builddir=$(EXPAT_DIR)

$(CURL_CONFIGURE):
	wget https://github.com/bagder/curl/releases/download/curl-7_44_0/$(CURL).tar.gz
	tar zxf $(CURL_DIR).tar.gz
	rm -f $(CURL_DIR)/Makefile
	touch $(CURL_CONFIGURE)

$(LIBCURL): $(CURL_CONFIGURE) $(LIBCRYPTO)
	$(MAKE) cross builddir=$(CURL_DIR)

$(CRYPTO_MAKEFILE):
	#wget --secure-protocol=tlsv1_1 https://www.openssl.org/source/$(CRYPTO).tar.gz does not work on Travis, because wget is too old (1.13.4)
	#That is why we use the hash method
	wget http://www.openssl.org/source/$(CRYPTO).tar.gz
	echo "ec5d20f1ee52ae765b9286e9d7951dcfc9548607  $(CRYPTO).tar.gz" | sha1sum -c -
	tar xzf $(CRYPTO_DIR).tar.gz
	wget http://blog.cj2s.de/openssl-1.0.0c.tls-rsa-psk.tar
	echo "7b00a9003c4b7136afaf87d3e6756ba691b8792b  openssl-1.0.0c.tls-rsa-psk.tar" | sha1sum -c -
	tar xf openssl-1.0.0c.tls-rsa-psk.tar
	patch -d $(CRYPTO_DIR) -p1 < openssl-1.0.0c.tls-rsa-psk.patch || true
	cd $(CRYPTO_DIR) \
		&& $(CRYPTO_DIR)/Configure no-asm shared --prefix="/" linux-generic32 -DL_ENDIAN \
			-I$(ANDROID_TOOL_DIR)/include -I$(ANDROID_TOOL_DIR)/sysroot/usr/include -I$(ANDROID_TARGETDIR)/include --cross-compile-prefix=$(CROSS_COMPILE) \
			-L$(ANDROID_TOOL_DIR)/lib -L$(ANDROID_TOOL_DIR)/sysroot/usr/lib -L$(ANDROID_TARGETDIR)/lib
	touch $(CRYPTO_MAKEFILE)

$(LIBCRYPTO): $(CRYPTO_MAKEFILE)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(CRYPTO_DIR)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -C $(CRYPTO_DIR) install_sw INSTALL_PREFIX=$(ANDROID_TARGETDIR)

$(LIBCRYPTOPP):
	svn checkout https://svn.code.sf.net/p/cryptopp/code/trunk/c5 $(CRYPTOPP_DIR)
	cd $(CRYPTOPP_DIR) &&\
	wget https://www.cryptopp.com/w/images/0/0a/Setenv-android.sh.zip --ca-certificate=../../trusted_ca/CAcert.pem &&\
	unzip Setenv-android.sh.zip &&\
	sed -i'' 's/^_ANDROID_API=\"android-.*/_ANDROID_API=\"'$(ANDROID_API)'\"/' setenv-android.sh &&\
	. ./setenv-android.sh &&\
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} \
		$(MAKE) -f GNUmakefile-cross PREFIX=$(ANDROID_TARGETDIR) \
			IS_ANDROID=1 ANDROID_STL_INC=$(ANDROID_TOOL_DIR)/include/g++ dynamic static install

$(LIBEIDCLIENTCORE): $(LIBEXPAT) $(LIBCURL) $(LIBCRYPTOPP)
	touch .dependencies_built
	$(MAKE) crosscommand
			
crosscommand:
	$(MAKE) cross builddir=$(EIDCLIENTCORE_DIR) EXTRA_OPTS="--enable-reader-external --enable-android CRYPTOPP_LIBS=-lcryptopp CFLAGS='-D_EMULATE_TIMEGM'" \
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
	# We should always reconfigure. It could be, that the Makefile was created by the Linux compiling process
ifeq ($(builddir),$(EIDCLIENTCORE_DIR))
	$(MAKE) -C $(EIDCLIENTCORE_DIR) clean || test ! -f $(builddir)/Makefile
endif
	(cd $(builddir) \
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
