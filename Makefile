SHELL=/bin/bash

PREFIX= $(shell pwd)

#BASIERT auf: https://github.com/BeID-lab/eIDClientCore/blob/master/README.md

ALL_DEPS = cryptopp asn1c libexpat openssl libcurl
MY_DEPS = cryptopp asn1c libexpat openssl libcurl

all:	$(MY_DEPS) eIDClient eIDClient_gui

mydeps: $(MY_DEPS)

clean: 
	rm -rf *[^Makefile]*

cryptopp:
	svn checkout https://svn.code.sf.net/p/cryptopp/code/trunk/c5 cryptopp
	sed -i.org -e "s%^#.*\(CXXFLAGS += -fPIC.*\)%\1%g" $(PREFIX)/cryptopp/GNUmakefile	
	make -C cryptopp all libcryptopp.so
	make -C cryptopp install PREFIX=$(PREFIX)

asn1c:
	wget http://lionet.info/soft/asn1c-0.9.24.tar.gz
	tar xzf asn1c-0.9.24.tar.gz
	cd asn1c-0.9.24 ;\
	./configure --prefix=$(PREFIX) ;\
	make install

libexpat:
	wget http://sourceforge.net/projects/expat/files/expat/2.1.0/expat-2.1.0.tar.gz
	tar xzf expat-2.1.0.tar.gz
	cd expat-2.1.0 ;\
	./configure --prefix=$(PREFIX) ;\
	make install
	
openssl:
	cd $(PREFIX)/OpenSSL_1_0_2-stable ;\
	git submodule init ;\
	git submodule update ;\
	patch -p1 <$(PREFIX)/patches/openssl/1.0.2/0001-add-Christian-J.-Dietrichs-RSA-PSK-patch.patch ;\
	patch -p1 <$(PREFIX)/patches/openssl/1.0.2/0002-fix-space-vs-tabs-indent.patch ;\
	patch -p1 <$(PREFIX)/patches/openssl/1.0.2/0003-add-missing-RSA_PSK-cipher-suites.patch ;\
	./config --prefix=$(PREFIX) shared ;\
	make ;\
	make install_sw

libcurl:
	wget http://curl.haxx.se/download/curl-7.32.0.tar.gz
	tar xzf curl-7.32.0.tar.gz
	cd curl-7.32.0 ;\
	./configure --prefix=$(PREFIX) PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig:$(PREFIX)/lib64/pkgconfig ;\
	make install

eIDClient:
	cd eIDClientCore ;\
	autoreconf -vis ;\
	env LD_LIBRARY_PATH=$(PREFIX)/lib:$(PREFIX)/lib64 ./configure --prefix=$(PREFIX) \
    	--with-openssl=$(PREFIX) --with-libcurl=$(PREFIX) \
    	PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig:$(PREFIX)/lib64/pkgconfig\
    	ASN1C=$(PREFIX)/bin/asn1c ;\
	sed -i.org -e "s%^\(CPPFLAGS = .*\)%\1 -DSKIP_PEER_VERIFICATION -DSKIP_HOSTNAME_VERIFICATION%g" \
	$(PREFIX)/eIDClientCore/lib/eIDClientConnection/Makefile ;\
	make install

eIDClient_gui:
	cd eIDClientCore/bin/Test_gui/ ;\
	qmake-qt5 -project main.cpp mainwindow.cpp mainwindow.h QT=widgets QMAKE_CXXFLAGS+=-std=c++11 INCLUDEPATH+="../../lib/eIDClientCore ../../lib ../../bin/SimpleClient" LIBS+="-L../../../lib -L../../../lib64 -leIDClientCore -lSimpleClient" ;\
	qmake-qt5 -makefile ;\
	make



