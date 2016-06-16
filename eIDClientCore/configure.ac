#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([eIDClientCore], [0.2])
AC_CONFIG_SRCDIR([bin/Test_nPAClientLib/Test_nPAClientLib.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
        LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
        AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

AC_ARG_ENABLE([android],
              [AS_HELP_STRING([--enable-android],[enable cross-compiling for android @<:@default=no@:>@])],
              ,
              [enable_android="no"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
AC_PATH_PROG(ASN1C, asn1c, false // Could not find asn1c //)
AC_CHECK_PROG(GENGETOPT_CHECK,gengetopt,yes)
AM_CONDITIONAL([HAS_GENGETOPT], [test "${GENGETOPT_CHECK}" = "yes"])
if test x"$GENGETOPT_CHECK" != x"yes" ; then
	AC_MSG_WARN([Please install gengetopt before installing.])
fi

# Do not look for wxWidgets when cross-compiling for android
AS_IF([test "x$enable_android" = "xno"], [
	AM_OPTIONS_WXCONFIG
	reqwx=3.0.0
	AM_PATH_WXCONFIG([$reqwx], [wxWin=1], [wxWin=0], [richtext])
	if test "$wxWin" != 1; then
	AC_MSG_ERROR([
		wxWidgets must be installed on your system.
	
		Please check that wx-config is in path, the directory
		where wxWidgets libraries are installed (returned by
		'wx-config --libs' or 'wx-config --static --libs' command)
		is in LD_LIBRARY_PATH or equivalent variable and
		wxWidgets version is $reqwx or above.
		])
	fi
	
	CPPFLAGS="$CPPFLAGS $WX_CPPFLAGS"
	CXXFLAGS="$CXXFLAGS $WX_CXXFLAGS_ONLY"
	CFLAGS="$CFLAGS $WX_CFLAGS_ONLY"
	LIBS="$LIBS $WX_LIBS"
])

# Do not use special C++11 settings when cross-compiling for android
AS_IF([test "x$enable_android" = "xno"], [
	AX_CXX_COMPILE_STDCXX_11([ext],[mandatory])
])
AX_PTHREAD([], AC_MSG_ERROR([pthread required])])
AX_CHECK_OPENSSL([AC_MSG_NOTICE([openssl found])], [AC_MSG_WARN([openssl not found])])
LIBCURL_CHECK_CONFIG()

# If you need to see the details, just run make V=1.
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for libraries.
PKG_CHECK_EXISTS([libcrypto++],
                 [PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++])],
                 [PKG_CHECK_EXISTS([cryptopp],
                                   [PKG_CHECK_MODULES([CRYPTOPP], [cryptopp])],
                                   [AC_MSG_WARN([libcrypto++ >= 0.12.1 not found by pkg-config])])])
PKG_CHECK_EXISTS([expat],
                 [PKG_CHECK_MODULES([EXPAT], [expat])],
                 [AC_MSG_WARN([expat not found by pkg-config])])
PKG_CHECK_EXISTS([libpcsclite],
                 [PKG_CHECK_MODULES([PCSC], [libpcsclite])],
                 [AC_MSG_WARN([libpcsclite not found by pkg-config])])

# FIXME since OpenSSL and Crypto++ are referenced in `lib/crypto.h`, all
# sublibraries need to include the definitions though they may not need the
# libraries
CXXFLAGS="$CXXFLAGS $OPENSSL_INCLUDES $CRYPTOPP_CFLAGS"
LIBS="$LIBS $CRYPTOPP_CFLAGS"

AC_ARG_WITH(
    [cygwin-native],
    [AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
    ,
    [with_cygwin_native="no"]
)
dnl Check for some target-specific stuff
case "${host}" in
    *-*-solaris*)
        CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
        LDFLAGS="${LDFLAGS} -L/usr/local/lib -R/usr/local/lib"
    ;;
    *-mingw*|*-winnt*)
        WIN32="yes"
        CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
    ;;
    *-cygwin*)
        AC_MSG_CHECKING([cygwin mode to use])
        if test "${with_cygwin_native}" = "yes"; then
            AC_MSG_RESULT([Using native win32])
            CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
            CFLAGS="${CFLAGS} -mno-cygwin"
            WIN32="yes"
        else
            AC_MSG_RESULT([Using cygwin])
            CPPFLAGS="${CPPFLAGS} -DCRYPTOKI_FORCE_WIN32"
        fi
    ;;
esac

if test "${WIN32}" = "yes"; then
    if test -z "PCSC_LIBS"; then
        PCSC_LIBS="-lwinscard"
    fi
else
    AC_CHECK_LIB([dl],
                 [dlopen],
                 ,
                 [AC_MSG_ERROR([libdl required])])
fi

saved_CPPFLAGS="$CPPFLAGS"
saved_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $PCSC_CFLAGS"
LIBS="$LDFLAGS $PCSC_LIBS"

DISABLE_PCSC=no
AC_CHECK_HEADERS(winscard.h, [],
                 [
                  AC_MSG_WARN([disabling PC/SC backend])
                  AC_DEFINE([DISABLE_PCSC], [1], [Define if PC/SC readers are disabled.])
                  DISABLE_PCSC=yes
                 ])

AC_MSG_CHECKING([for SCardTransmit])
AC_TRY_LINK_FUNC(SCardTransmit,
                 [AC_MSG_RESULT([yes])],
                 [
                  AC_MSG_WARN([disabling PC/SC backend])
                  AC_DEFINE([DISABLE_PCSC], [1], [Define if PC/SC readers are disabled.])
                  DISABLE_PCSC=yes
                 ])
AM_CONDITIONAL([DISABLE_PCSC], [test "${DISABLE_PCSC}" = "yes"])

AC_ARG_ENABLE([reader-external],
              [AS_HELP_STRING([--enable-reader-external],[enable External Reader @<:@default=no@:>@])],
              ,
              [enable_reader_external="no"])
AM_CONDITIONAL([DISABLE_EXTERNAL], [test "${enable_reader_external}" = "no"])
if test "${enable_reader_external}" = "no"
then
    AC_DEFINE([DISABLE_EXTERNAL], [1], [Define if External reader is disabled.])
fi

CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"


saved_CPPFLAGS="$CPPFLAGS"
saved_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $EIDGUI_CFLAGS"
LIBS="$LDFLAGS $EIDGUI_LIBS"

AC_CHECK_HEADERS(eIDmfcUI.h, [],
                 [
                  AC_MSG_WARN([disabling eID GUI])
                  AC_DEFINE([DISABLE_EIDGUI], [1], [Define if MFC eID GUI is disabled.])
                  DISABLE_EIDGUI=yes
                 ])

AC_MSG_CHECKING([for eIDmfcUIdoPace])
AC_TRY_LINK_FUNC(eIDmfcUIdoPace,
                 [
                  AC_MSG_RESULT([yes])
                 ],
                 [
                  AC_MSG_RESULT([no])
                  AC_MSG_WARN([disabling eID GUI])
                  AC_DEFINE([DISABLE_EIDGUI], [1], [Define if MFC eID GUI is disabled.])
                  DISABLE_EIDGUI=yes
                 ])
AM_CONDITIONAL([DISABLE_EIDGUI], [test "${DISABLE_EIDGUI}" = "yes"])

CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([netdb.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
# Do not use malloc settings when cross-compiling for android
AS_IF([test "x$enable_android" = "xno"], [
	AC_FUNC_MALLOC
])
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset select socket strchr strdup strerror strstr strtoul])
#AC_CHECK_DECL(pthread_cancel,,, [#include <pthread.h>])


AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])

cat << EOF

${PACKAGE} has been configured with following options:

Version:                   ${PACKAGE_VERSION}
User binaries:             $(eval eval eval echo "${bindir}")
Libraries:                 $(eval eval eval echo "${libdir}")
Configuration files:       $(eval eval eval echo "${sysconfdir}")


Host:                      ${host}
Compiler:                  ${CXX}
Preprocessor flags:        ${CPPFLAGS}
Compiler flags:            ${CFLAGS}
Linker flags:              ${LDFLAGS}
Libraries:                 ${LIBS}
PTHREAD_LIBS:              ${PTHREAD_LIBS}
PTHREAD_CFLAGS:            ${PTHREAD_CFLAGS}
PTHREAD_CC:                ${PTHREAD_CC}
PCSC_CFLAGS:               ${PCSC_CFLAGS}
PCSC_LIBS:                 ${PCSC_LIBS}
EXPAT_CFLAGS:              ${EXPAT_CFLAGS}
EXPAT_LIBS:                ${EXPAT_LIBS}
CRYPTOPP_CFLAGS:           ${CRYPTOPP_CFLAGS}
CRYPTOPP_LIBS:             ${CRYPTOPP_LIBS}
OPENSSL_INCLUDES:          ${OPENSSL_INCLUDES}
OPENSSL_LIBS:              ${OPENSSL_LIBS}
OPENSSL_LDFLAGS:           ${OPENSSL_LDFLAGS}
LIBCURL:                   ${LIBCURL}
LIBCURL_CPPFLAGS:          ${LIBCURL_CPPFLAGS}
ASN1C:                     ${ASN1C}

eID MFC GUI disabled:      ${DISABLE_EIDGUI}
PC/SC reader disabled:     ${DISABLE_PCSC}
External reader enabled:   ${enable_reader_external}

EOF

AC_CONFIG_FILES([Makefile
                 bin/Makefile
                 bin/SimpleClient/eidui_gui/Makefile
                 bin/Test_nPAClientLib/Makefile
                 bin/SimpleClient/Makefile
                 lib/Makefile
                 lib/eCardCore/Makefile
                 lib/eIDClientConnection/Makefile
                 lib/eidasn1/Makefile
                 lib/nPA-EAC/Makefile
                 lib/eIDClientCore/Makefile])
AC_OUTPUT
