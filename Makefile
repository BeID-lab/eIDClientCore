SHELL=/bin/bash

PREFIX ?= $(shell pwd)

ASN1C ?= "$(PREFIX)/bin/asn1c"

#INSECURE = "true"

#BASIERT auf: https://github.com/BeID-lab/eIDClientCore/blob/master/README.md

ALL_DEPS = cryptopp asn1c libexpat openssl libcurl
MY_DEPS = cryptopp asn1c libexpat openssl libcurl

all:	$(MY_DEPS) eIDClient

mydeps: $(MY_DEPS)

delete_all: 
	rm -rf *[^Makefile]*

clean_cryptopp: 
	make -C cryptopp*/ clean

clean_asn1c:
	make -C asn1c*/ clean

clean_libexpat:
	make -C expat*/ clean

clean_openssl:
	make -C OpenSSL*/ clean

clean_libcurl:
	make -C curl*/ clean

clean_eIDClient:
	make -C eIDClientCore/ clean

clean: clean_cryptopp clean_asn1c clean_libexpat clean_openssl clean_libcurl clean_eIDClient

cryptopp:
	svn checkout https://svn.code.sf.net/p/cryptopp/code/trunk/c5 cryptopp
	sed -i.org -e "s%^#.*\(CXXFLAGS += -fPIC.*\)%\1%g" cryptopp/GNUmakefile	
	make -C cryptopp all libcryptopp.so
	make -C cryptopp install PREFIX=$(PREFIX)

asn1c:
	wget https://sourceforge.net/projects/asn1c/files/asn1c/asn1c-0.9.24/asn1c-0.9.24.tar.gz
	tar xzf asn1c-0.9.24.tar.gz
	cd asn1c-0.9.24 ;\
	./configure --prefix=$(PREFIX) ;\
	make install

libexpat:
	wget https://github.com/libexpat/libexpat/releases/download/R_2_1_0/expat-2.1.0.tar.gz
	echo "823705472f816df21c8f6aa026dd162b280806838bb55b3432b0fb1fcca7eb86 expat-2.1.0.tar.gz" | sha256sum -c - ;\
	tar xzf expat-2.1.0.tar.gz
	cd expat-2.1.0 ;\
	./configure --prefix=$(PREFIX) ;\
	make install
	
openssl:
	cd OpenSSL ;\
	git submodule init ;\
	git submodule update ;\
	./config --prefix=$(PREFIX) shared ;\
	make -j8 ;\
	make install_sw ;\
	apps/openssl ciphers 'RSAPSK' -v ;\
	if test $$? -ne 0 ; then \
		echo "No RSA-PSK cipher suites found. OpenSSL build some somehow failed!" ;\
		exit 1 ;\
	fi

libcurl:
	wget https://github.com/bagder/curl/releases/download/curl-7_44_0/curl-7.44.0.tar.gz
	tar xzf curl-7.44.0.tar.gz
	cd curl-7.44.0 ;\
	./configure --prefix=$(PREFIX) PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig:$(PREFIX)/lib64/pkgconfig ;\
	make install

eIDClient:
	cd eIDClientCore ;\
	autoreconf -vis ;\
	env LD_LIBRARY_PATH=$(PREFIX)/lib:$(PREFIX)/lib64 ./configure --prefix=$(PREFIX) \
    	--with-openssl=$(PREFIX) --with-libcurl=$(PREFIX) \
    	PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig:$(PREFIX)/lib64/pkgconfig\
    	ASN1C="$(ASN1C)" CRYPTOPP_CFLAGS="-I$(PREFIX)/include" CRYPTOPP_LIBS="-L$(PREFIX)/lib -lcryptopp"
	[[ -v INSECURE ]] || \
		sed -i.org -e "s%^\(CPPFLAGS = .*\)%\1 -DSKIP_PEER_VERIFICATION -DSKIP_HOSTNAME_VERIFICATION%g"\
			eIDClientCore/lib/eIDClientConnection/Makefile ;\
	make -C eIDClientCore install
