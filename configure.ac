#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([eIDClientCore], [0.1])
AC_CONFIG_SRCDIR([bin/Test_nPAClientLib/Test_nPAClientLib.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_PROG_LIBTOOL
	]
)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PATH_PROG(ASN1C, asn1c, false // Could not find asn1c //)
AC_PATH_PROG(WGET, wget, false // Could not find wget //)
AC_PATH_PROG(AUTORECONF, autoreconf, false // Could not find autoreconf //)

# If you need to see the details, just run make V=1.
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for libraries.
PKG_CHECK_EXISTS([libcrypto++],
                 [PKG_CHECK_MODULES([CRYPTOPP], [libcrypto++])],
                 [AC_MSG_WARN([libcrypto++ >= 0.12.1 not found by pkg-config])])
PKG_CHECK_EXISTS([expat],
                 [PKG_CHECK_MODULES([EXPAT], [expat])],
                 [AC_MSG_WARN([expat not found by pkg-config])])
if test -z "$EXPAT_LIBS"
then
    EXPAT_LIBS="-lexpat"
fi
# Checks for libraries.
PKG_CHECK_EXISTS([libpcsclite],
                 [PKG_CHECK_MODULES([PCSC], [libpcsclite])],
                 [AC_MSG_WARN([libpcsclite not found by pkg-config])])
PKG_CHECK_EXISTS([gnutls],
                 [PKG_CHECK_MODULES([GNUTLS], [gnutls])],
                 [AC_MSG_WARN([gnutls not found by pkg-config])])
if test -z "${GNUTLS_LIBS}"
then
    BUILD_GNUTLS=yes
else
    BUILD_GNUTLS=no
fi


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


CPPFLAGS="$PCSC_CFLAGS $CPPFLAGS"

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
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset select socket strchr strdup strerror strstr strtoul])


AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([BUILD_GNUTLS], [test "${BUILD_GNUTLS}" = "yes"])


cat << EOF

${PACKAGE} has been configured with following options:

Version:              ${PACKAGE_VERSION}
User binaries:        $(eval eval eval echo "${bindir}")
Libraries:            $(eval eval eval echo "${libdir}")
Configuration files:  $(eval eval eval echo "${sysconfdir}")


Host:                 ${host}
Compiler:             ${CXX}
Preprocessor flags:   ${CPPFLAGS}
Compiler flags:       ${CFLAGS}
Linker flags:         ${LDFLAGS}
Libraries:            ${LIBS}
PCSC_CFLAGS:          ${PCSC_CFLAGS}
PCSC_LIBS:            ${PCSC_LIBS}
EXPAT_CFLAGS:         ${EXPAT_CFLAGS}
EXPAT_LIBS:           ${EXPAT_LIBS}
CRYPTOPP_CFLAGS:      ${CRYPTOPP_CFLAGS}
CRYPTOPP_LIBS:        ${CRYPTOPP_LIBS}
Build GnuTLS:         ${BUILD_GNUTLS}
GNUTLS_CFLAGS:        ${GNUTLS_CFLAGS}
GNUTLS_LIBS:          ${GNUTLS_LIBS}

EOF

AC_CONFIG_FILES([Makefile
                 bin/Makefile
                 bin/Test_nPAClientLib/Makefile
                 lib/Makefile
                 lib/eCardCore/Makefile
                 lib/eIDClientConnection/Makefile
                 lib/eidasn1/Makefile
                 lib/nPA-EAC/Makefile
                 lib/eIDClientCore/Makefile])
AC_OUTPUT
