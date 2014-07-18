# Welcome

All relevant information about the eIDClientCore can be found at:
http://sar.informatik.hu-berlin.de/BeID-lab/eIDClientCore

Warning: This is just proof-of-concept code and should _NOT_ be used in
production environments

## Tested platforms:

* Windows
* Linux
* Mac OS X
* Android
* iOS

## Usage

### C library interface

For using eIDClientCore applications should use
[eIDClientCore.h](lib/eIDClientCore/eIDClientCore.h)
The application initiates the electronic identification by calling
`nPAeIdPerformAuthenticationProtocol`. To enter the PIN, the application shall
define a user interaction call back. Also, the state call back informs the
application about completed protocol steps.

The application may also choose to use
[eIDClientConnection.h](lib/eIDClientConnection/eIDClientConnection.h)
which, by default, is basically a wrapper around libcurl. However, you may want
to choose to replace the implementation of eIDClientConnection with a wrapper
to your platform dependent solution.

### JNI wrappers for Android

For android we build JNI wrappers to our C++ implementation. The public
Java interface is accessed through the
[EidClient class](android/eIDClientLib/src/de/bdr/eidclient/EidClient.java)
Electronic identification is triggered similar to its C-counterpart.
Additionally the Android application has to pass an implementation of the
[Reader class](android/eIDClientLib/src/de/bdr/eidclient/reader/Reader.java)
to do the actual communication with the card.

# Building for Linux

In the following guide we assume that PREFIX is set to the target installation
directory.

## Compiling Prerequisites from source

eIDClientCore has the following dependencies:
* Crypto++
* asn1c (at least version 0.9.23)
* libexpat
* PC/SC development files (if PC/SC smart card readers shall be used)
* OpenSSL patched for RSA-PSK
* libcurl (using the patched OpenSSL)

### Crypto++

```sh
svn checkout https://svn.code.sf.net/p/cryptopp/code/trunk/c5 cryptopp
sed -i.org -e "s%^#.*\(CXXFLAGS += -fPIC.*\)%\1%g" ${PREFIX}/cryptopp/GNUmakefile
make -C cryptopp all libcryptopp.so
make -C cryptopp install PREFIX=${PREFIX}
```

You can skip compilation of Crypto++ when using your distributions version of
the library.

### asn1c

```sh
wget http://lionet.info/soft/asn1c-0.9.24.tar.gz
tar xzf asn1c-0.9.24.tar.gz
cd asn1c-0.9.24
./configure --prefix=${PREFIX}
make install
cd -
```

If you want to use your distributions version of asn1c you will propably have
to edit
[eidasn1's Makefile.am](lib/eidasn1/Makefile.am#L1-9).
You need to change the commented lines so that they meet the version of asn1c.

### libexpat

```sh
wget http://sourceforge.net/projects/expat/files/expat/2.1.0/expat-2.1.0.tar.gz
tar xzf expat-2.1.0.tar.gz
cd expat-2.1.0
./configure --prefix=${PREFIX}
make install
cd -
```

You can skip compilation of libexpat when using your distributions version of
the library.

### OpenSSL

```sh
wget http://www.openssl.org/source/openssl-1.0.0k.tar.gz
tar xzf openssl-1.0.0k.tar.gz
wget http://blog.cj2s.de/openssl-1.0.0c.tls-rsa-psk.tar
tar xf openssl-1.0.0c.tls-rsa-psk.tar
patch -d openssl-1.0.0k -p1 < openssl-1.0.0c.tls-rsa-psk.patch
cd openssl-1.0.0k
./config --prefix=${PREFIX} shared
make
make install_sw
cd -
```

OpenSSL is the only library that needs to be patched since it does currently
not support RSA-PSK. Please note that we are working on a better patch for
newer version of OpenSSL.

### libcurl

```sh
wget http://curl.haxx.se/download/curl-7.32.0.tar.gz
tar xzf curl-7.32.0.tar.gz
cd curl-7.32.0
./configure --prefix=${PREFIX} \
    PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:${PREFIX}/lib64/pkgconfig
make install
cd -
```

If you want to use your distributions version of curl will need to make sure it
uses the patched version of OpenSSL at runtime (see above).

## Compiling eIDClientCore from source

```sh
git clone https://github.com/BeID-lab/eIDClientCore.git
cd eIDClientCore
autoreconf -vis
env LD_LIBRARY_PATH=${PREFIX}/lib:${PREFIX}/lib64 ./configure --prefix=${PREFIX} \
    --with-openssl=${PREFIX} --with-libcurl=${PREFIX} \
    PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:${PREFIX}/lib64/pkgconfig \
    ASN1C=${PREFIX}/bin/asn1c
make install
cd -
```

# Building for Android

We added a Makefile to automatically build eIDClientCore and its prerequisites
for android. We assume that ANDROID_NDK_ROOT and ANDROID_SDK_ROOT are set to
the root directory of Android's SDK and NDK respectively. Also, asn1c and ant
should be available in the PATH.

```sh
git clone https://github.com/BeID-lab/eIDClientCore.git
cd eIDClientCore/android
make ANDROID_NDK_ROOT=$ANDROID_NDK_ROOT ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT
```
On successfull compilation you can find a jar-file containing the library in
eIDClientCore/android. Building for android has been verified on Debian/Wheezy
with android-ndk-r9 and adt-bundle-linux-x86-20130729.

* ANDROID_API defines the Android API version to use, we choose 'android-14' as
  default
* ANDROID_ARCH defines the architecture to use, we choose 'arm' as default

## Including the library in your Android project

To use the library in your project, you have two possibilities:

1. Add eIDClientLib/bin/classes.jar to your build path _and_ copy the following
   listed shared objects into your libs/armeabi folder:
   * libeidclient-wrapper.so
   * libexternalReader.so
   * libstlport_shared.so

2. Reference the library with the android tools (see [Android
   documentation](http://developer.android.com/tools/projects/projects-cmdline.html#ReferencingLibraryProject)).
   In this case all necessary files are copied automatically.

```sh
android update project \
  --path path/to/your/project \
  --library path/to/eiDClientLib
```


# TODO

* Add abstraction layer between ePACard and cryptographic functions
* Remove unused/bloated interfaces
* Check try...catch block around C-Interfaces
* use OOP in nPA-EAC
* Check the hash of the SSL/TLS certificate from the SP with the SP's Terminal certificate
* Check if the Terminal certificate is up to date
* Check the Subject URL of the Terminal certificate
* remove the use of exceptions
