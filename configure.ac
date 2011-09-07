#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2009-2011  The OpenDKIM Project.  All rights reserved.
# 
# $Id: configure.ac,v 1.185 2010/10/28 04:35:44 cm-msk Exp $

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 2)
m4_define([VERSION_MAJOR_REV], 5)
m4_define([VERSION_MINOR_REV], 0)
m4_define([VERSION_PATCH], 0)

#
# Library version
# 	- bump "current" and reset "revision" with API changes
# 	- bump "revision" with internal source code changes
#
m4_define([LIBVERSION_CURRENT], 6)
m4_define([LIBVERSION_REVISION], 0)
m4_define([LIBVERSION_AGE], 0)

#
# Autotools setup
#
AC_INIT([OpenDKIM],
        [VERSION_RELEASE.VERSION_MAJOR_REV.VERSION_MINOR_REV],
        [bugs@opendkim.org])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([libar/ar.c])
AC_CONFIG_HEADERS([build-config.h])

AC_CONFIG_MACRO_DIR([m4])

#
# Hexadecimal version, for use in generating dkim.h
# 
HEX_VERSION=$(printf %08x $(( ((VERSION_RELEASE << 8 | VERSION_MAJOR_REV) << 8 | VERSION_MINOR_REV) << 8| VERSION_PATCH )))
AC_SUBST([HEX_VERSION])

#
# library version, passed to libtool
# 
LIBOPENDKIM_VERSION_INFO=$(printf %d:%d:%d LIBVERSION_CURRENT LIBVERSION_REVISION LIBVERSION_AGE)
AC_SUBST([LIBOPENDKIM_VERSION_INFO])

#
# Checks for programs
#
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

#
# Check for how to compile threaded stuff
#
AX_PTHREAD

#
# Checks for libraries
#
AC_SEARCH_LIBS(inet_addr, nsl)
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_SEARCH_LIBS(inet_pton, resolv,
               AC_DEFINE(HAVE_INET_PTON, 1,
                         [Define to 1 if you have the `inet_pton()' function.]))
AC_SEARCH_LIBS(inet_ntop, resolv,
               AC_DEFINE(HAVE_INET_NTOP, 1,
                        [Define to 1 if you have the `inet_ntop()' function.]))
AC_SEARCH_LIBS(getaddrinfo, resolv,
               AC_DEFINE(HAVE_GETADDRINFO, 1,
                         [Define to 1 if you have the `getaddrinfo()' function.]))
AC_SEARCH_LIBS(res_ninit, resolv,
               AC_DEFINE(HAVE_RES_NINIT, 1,
                         [Define to 1 if you have the `res_ninit()' function.]))


AC_HEADER_RESOLV

#
# Check for types
#

AC_CHECK_TYPES([useconds_t])

#
# See if libopendkim will need -lresolv
#
dnscheck='
#include "confdefs.h" 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h> 
int main() {
res_mkquery (0, 0, 0, 0, 0, 0, 0, 0, 0);
dn_expand (0, 0, 0, 0, 0);
dn_skipname (0, 0);
dn_comp (0, 0, 0, 0, 0);
return 0;
}'
AC_MSG_CHECKING([whether the resolver works without -lresolv])
AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
])] , [
	AC_MSG_RESULT(yes)
	LIBRESOLV=
] , [
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([whether the resolver works with -lresolv])
	saved_LIBS="$LIBS"
	LIBS=-lresolv
	AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
	])] , [
		AC_MSG_RESULT(yes)
		LIBRESOLV=-lresolv
	] , [
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([need workable resolver library])
	])
	LIBS="$saved_LIBS"
])
AC_SUBST([LIBRESOLV])
 
#
# Checks for header files
#
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h iso/limits_iso.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h stdint.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

#
# Checks for library functions.
#
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC

AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gethostbyname  gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul strtoull strlcpy strlcat])

#
# Checks for structure members
#
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
                AC_DEFINE([HAVE_SUN_LEN],
                          [1],
                          [Define if sockaddr_un has a sun_len member]),
                [],
                [[#include <sys/un.h>]])

#
# Library feature string and macros
#
LIBOPENDKIM_FEATURE_STRING="libopendkim $PACKAGE_VERSION:"

AC_DEFUN([TR_UP], [m4_translit([AS_TR_SH([$1])], [a-z], [A-Z])])

AC_DEFUN([FEATURE],
         [notincluded="(Not enabled for this installation.)"
          AC_ARG_ENABLE($1, AS_HELP_STRING(--enable-$1, $2),
                        AS_IF([test "x$enable_]$1[" = "xyes"],
                              [
				AC_SUBST(TR_UP($1)[_MANNOTICE], "")
				AC_DEFINE(TR_UP($1), 1, [enable $1 feature])
			      ],
			      [
				AC_SUBST(TR_UP($1)[_MANNOTICE], $notincluded)
			      ]),
                        AC_SUBST(TR_UP($1)[_MANNOTICE], $notincluded))
         ])

AC_DEFUN([LIB_FEATURE],
         [FEATURE($1, $2)
          AS_IF([test "x$enable_]$1[" = "xyes"],
	        [
			LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING $1"
		])
         ])

AC_DEFUN([FFR_FEATURE],
         [experimentalnotincluded="(Experimental feature not enabled for this installation.)"
          AC_ARG_ENABLE($1, AS_HELP_STRING(--enable-$1, $2),
                        AS_IF([test "x$enable_]$1[" = "xyes"],
                              [
				AC_DEFINE([_FFR_]TR_UP($1), 1,
				          [enable $1 feature])
				AC_SUBST(TR_UP($1)[_MANNOTICE],
				         "(Note: Feature is experimental.)")
                              ],
                              [
				AC_SUBST(TR_UP($1)[_MANNOTICE],
				         $experimentalnotincluded)
                              ]),
                        AC_SUBST(TR_UP($1)[_MANNOTICE],
                                 $experimentalnotincluded))
         ])

AC_DEFUN([LIB_FFR_FEATURE],
         [FFR_FEATURE($1, $2)
          AS_IF([test "x$enable_]$1[" = "xyes"],
                [
			LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING $1"
		])
         ])

#
# opendkim
#
FEATURE([popauth], [enable POP-before-SMTP support])

FEATURE([poll], [use poll() instead of select()])

FFR_FEATURE([atps], [experimental Authorized Third Party Signers checks])
LIB_FFR_FEATURE([atps], [experimental Authorized Third Party Signers checks])
AM_CONDITIONAL([ATPS], [test x"$enable_atps" = x"yes"])

FFR_FEATURE([adsp_lists], [support for ADSP filtering for lists])

FFR_FEATURE([db_handle_pools], [experimental database handle pools])

FFR_FEATURE([diffheaders], [compare signed and verified headers when possible])
LIB_FFR_FEATURE([diffheaders],
                [compare signed and verified headers when possible])

FFR_FEATURE([dkim_reputation], [experimental DKIM reputation checks])
LIB_FFR_FEATURE([dkim_reputation], [experimental DKIM reputation checks])
AM_CONDITIONAL([DKIM_REPUTATION], [test x"$enable_dkim_reputation" = x"yes"])

FFR_FEATURE([identity_header], [special header to set identity])

FFR_FEATURE([ldap_caching], [LDAP query piggybacking and caching])

FFR_FEATURE([lua_globals], [passing of global variabls between Lua scripts])

FFR_FEATURE([oversign], [enable header field over-signing])

FFR_FEATURE([postgresql_reconnect_hack],
            [hack to overcome PostgreSQL connection error detection bug])

FFR_FEATURE([rate_limit], [support for DKIM-based rate limiting])

FFR_FEATURE([replace_rules], [support for string substitution when signing])

FFR_FEATURE([report_intervals],
            [support for requested report intervals when reporting])

FFR_FEATURE([redirect],
            [support for redirecting failed verifications to a mailbox])

FFR_FEATURE([resign],
            [support for one-step re-signing])

FFR_FEATURE([select_canonicalization],
            [allow sender to select canonicalization])

FFR_FEATURE([selector_header], [special header to choose signing key])

FFR_FEATURE([sender_macro], [macro to determine sender])

FFR_FEATURE([stats], [stats recording and reporting])
AM_CONDITIONAL([STATS], [test x"$enable_stats" = x"yes"])
FFR_FEATURE([statsext], [extended stats recording and reporting])

FFR_FEATURE([rbl], [Realtime Blacklist query support])
AM_CONDITIONAL([RBL], [test x"$enable_rbl" = x"yes"])

FFR_FEATURE([vbr], [Vouch-By-Reference support])
AM_CONDITIONAL([VBR], [test x"$enable_vbr" = x"yes"])

LIB_FFR_FEATURE([xtags], [extension signature tags])

if test x"$enable_statsext" = x"yes" -a x"$enable_stats" != x"yes"
then
	AC_MSG_ERROR([--enable-statsext requires --enable-stats])
fi

if test x"$enable_atps" = x"yes" -a x"$enable_xtags" != x"yes"
then
	AC_MSG_ERROR([--enable-atps requires --enable-xtags])
fi

FFR_FEATURE([default_sender], [default sender address])

# sendmail command

AC_PATH_PROG([SENDMAIL_PATH], [sendmail], [/usr/sbin/sendmail],
             [/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/lib:$PATH])
AC_DEFINE_UNQUOTED([SENDMAIL_PATH], "$ac_cv_path_SENDMAIL_PATH",
                   [The path the the sendmail executable for report sending])
AC_SUBST([SENDMAIL_PATH])

#
# use rpath at load time?
#

AC_ARG_ENABLE([rpath],
	AS_HELP_STRING([--enable-rpath],
	               [include library load paths in binaries]))
AM_CONDITIONAL([RPATH], [test x"$enable_rpath" = x"yes"])

#
# test coverage/profiling stuff
# 
AC_ARG_ENABLE([codecoverage],
	AS_HELP_STRING([--enable-codecoverage],
	               [include code coverage/profiling code]))
if test x"$enable_codecoverage" = x"yes"
then
	# gcc can do all of them; Solaris cc can only do gprof
	AC_CHECK_PROG([hasgcc], [gcc], [yes])
	AC_CHECK_PROG([hascc], [cc], [yes])
	if test x"$hasgcc" != x"yes" -a x"$hascc" = x"yes"
	then
		if test x`cc -V 2>&1 | grep -c "Sun C"` = x"1"
		then
			hassuncc="yes"
		fi
	fi

	# figure out which profiling system to use
	AC_CHECK_PROG([hasgprof], [gprof], [yes])
	AC_ARG_WITH(gprof,
		AS_HELP_STRING(--with-gprof, profiling with gprof),
		hasgprof="$withval")
	if test x"$hasgcc" = x"yes"
	then
		AC_CHECK_PROG([hasgcov], [gcov], [yes])
		AC_ARG_WITH(gcov,
			AS_HELP_STRING(--with-gcov, profiling with gcov),
			hasgcov="$withval")
		AC_CHECK_PROG([haslcov], [lcov], [yes])
		AC_ARG_WITH(lcov,
			AS_HELP_STRING(--with-lcov, profiling with lcov),
			haslcov="$withval")
	fi

	# bail if none
	if test x"$hasgprof" != x"yes" -a \
		x"$hasgcov" != x"yes" -a \
		x"$haslcov" != x"yes"
	then
		AC_MSG_ERROR([no supported test coverage packages found])
	fi

	# see if there's a libgcov (OpenBSD doesn't have one)
	if test x"$hasgcov" = x"yes" -a x"$haslcov" != x"yes"
	then
		saved_LIBS="$LIBS"
		LIBS=""
		AC_SEARCH_LIBS([__gcov_init], [gcov])
		GCOV_LIBS="$LIBS"
		LIBS="$saved_LIBS"
	fi

	COV_CFLAGS=""
	COV_LDFLAGS=""
	COV_LIBADD=""

	# sun profiling
	if test x"$hasgprof" = x"yes" -a \
	        x"$hasgcov" != x"yes" -a \
	        x"$hassuncc" = x"yes"
	then
		COV_CFLAGS="-g -xpg"
		COV_LDFLAGS="-g -xpg"
	# non-sun profiling
	elif test x"$hasgprof" = x"yes" -a \
		x"$hasgcov" != x"yes" -a \
		x"$hassuncc" != x"yes"
	then
		COV_CFLAGS="-g -pg"
		COV_LDFLAGS="-g -pg"
	# gcov profiling
	elif test x"$hasgcov" = x"yes"
	then
		COV_CFLAGS="-g -fprofile-arcs -ftest-coverage"
		COV_LIBADD="$GCOV_LIBS"
	fi

	AC_SUBST(COV_CFLAGS)
	AC_SUBST(COV_LDFLAGS)
	AC_SUBST(COV_LIBADD)
fi

# see if profiling-enabled binaries generate profile output with the
# standard name "gmon.out" or "<file>.gmon"

gprof_gmon_out="unknown"
if test x"$hasgprof" = x"yes"
then
	gprofcheck='
int main() {
	long x;

	x = random();
}'
	AC_MSG_CHECKING([names of profiling output files])

	saved_CFLAGS="$CFLAGS"
	saved_LDFLAGS="$LDFLAGS"

	CFLAGS="$CFLAGS $COV_CFLAGS"
	LDFLAGS="$LDFLAGS $COV_LDFLAGS"

	AC_RUN_IFELSE([AC_LANG_SOURCE([$gprofcheck])],
	              [	if test -f "gmon.out"
			then
				gprof_gmon_out="yes"
				rm -f gmon.out
				AC_MSG_RESULT(gmon.out)
			else
				gprof_gmon_out="no"
				rm -f *.gmon
				AC_MSG_RESULT([<binary>.gmon])
			fi
	              ],
	              [AC_MSG_RESULT(unknown)])

	CFLAGS="$saved_CFLAGS"
	LDFLAGS="$saved_LDFLAGS"
fi

AM_CONDITIONAL(LCOV, test x"$haslcov" = x"yes" -a x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV, test x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV_ONLY, test x"$hasgcov" = x"yes" -a x"$haslcov" != x"yes")
AM_CONDITIONAL(GPROF, test x"$hasgprof" = x"yes" -a x"$hasgcov" != x"yes")
AM_CONDITIONAL(GPROF_FILENAMES, test x"$gprof_gmon_out" = x"no")

#
# opendkim
# 
AC_ARG_ENABLE([filter],
              AS_HELP_STRING([--disable-filter],
                             [do not compile the opendkim filter]),
              [enable_filter=$enableval],
              [enable_filter=yes])
AM_CONDITIONAL([BUILD_FILTER], [test x"$enable_filter" != x"no"])

#
# libopendkim
#
LIB_FEATURE([query_cache], [local key/policy caching])

LIB_FFR_FEATURE([parsetime], [parse From: headers for sending times])

#
# Conditional stuff
#
AC_ARG_ENABLE([allsymbols],
              AS_HELP_STRING([--enable-allsymbols],
                             [export internal-use symbols for better test coverage]))
AM_CONDITIONAL(ALL_SYMBOLS, [test x"$enable_allsymbols" = x"yes"])

AC_ARG_ENABLE([arlib],
              AS_HELP_STRING([--enable-arlib],
                             [enable provided asynchronous resolver library]),
              AS_IF([test "x$enable_arlib" = "xyes"],
              [
		AC_DEFINE(USE_ARLIB, 1,
		          [enable provided asynchronous resolver library])
              ])
)

AM_CONDITIONAL([USE_ARLIB], [test x"$enable_arlib" = x"yes"])

AC_ARG_ENABLE([debug],
              AS_HELP_STRING([--enable-debug],
	                     [produce debugging binaries and libraries]),
              AS_IF([test "x$enable_debug" = x"yes"],
		[
			LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING debug"
			[[CFLAGS=`echo $CFLAGS | sed 's/ -O[0-9s]*//g'`]]
		])
)

AM_CONDITIONAL([DEBUG], [test x"$enable_debug" = x"yes"])

#
# gnutls
#

AC_ARG_WITH([gnutls],
            AS_HELP_STRING([--with-gnutls],
                           [location of GnuTLS includes and library]),
            [gtpath="$withval"], [gtpath="no"])

gnutls_found="no"

if test \( x"$gtpath" = x"auto" -o x"$gtpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([GNUTLS], [libgnutls >= 2.11.7],
	                  [gnutls_found="yes"],
	                  [gnutls_found="auto"
	                   AC_MSG_WARN([pkg-config for GnuTLS not found, trying manual search...])
	                  ])
elif test x"$gtpath" != x"no"
then
	AC_MSG_NOTICE([checking for GnuTLS library and includes in $gtpath])

	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	LIBS="-lgnutls $saved_LIBS"
	CPPFLAGS="-I$gtpath/include $saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	LDFLAGS="-L$gtpath/lib $saved_LDFLAGS"

	AC_CHECK_HEADERS([gnutls/gnutls.h], ,
                         AC_MSG_ERROR([required GnuTLS header not found]))

	AC_SEARCH_LIBS([gnutls_global_init], [gnutls], ,
                       AC_MSG_ERROR([libgnutls not found]),
	               [-lnettle -lgmp -ldl])

	LIBCRYPTO_CPPFLAGS="-I$gtpath/include"
	LIBCRYPTO_LIBDIRS="-L$gtpath/lib"
	LIBCRYPTO_LIBS="-lgnutls"

	CFLAGS="$saved_CFLAGS"
	CPPFLAGS="$saved_CPPFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"

	gnutls_found="yes"
fi

if test x"$gtpath" = x"yes" -a x"$gnutls_found" = x"auto"
then
	gcdirs="/usr/local /usr"

	for d in $gcdirs
	do
		AC_MSG_NOTICE([checking for GnuTLS library and includes in $d])

		saved_CFLAGS="$CFLAGS"
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		saved_LIBS="$LIBS"

		LIBS="-lgnutls $saved_LIBS"
		CPPFLAGS="-I$d/include $saved_CPPFLAGS"
		CFLAGS="$saved_CFLAGS"
		LDFLAGS="-L$d/lib $saved_LDFLAGS"

		gnutls_h_found="no"
		gnutls_lib_found="no"

		AC_CHECK_HEADERS([gnutls/gnutls.h], gnutls_h_found="yes")
		AC_SEARCH_LIBS([gnutls_global_init], [gnutls],
		               gnutls_lib_found="yes", , [-lnettle -lgmp])

		CFLAGS="$saved_CFLAGS"
		CPPFLAGS="$saved_CPPFLAGS"
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$saved_LIBS"

		if test x"$gnutls_h_found" = x"yes" -a \
		        x"$gnutls_lib_found" = x"yes"
		then
			LIBCRYPTO_CPPFLAGS="-I$d/include"
			LIBCRYPTO_LIBDIRS="-L$d/lib"
			LIBCRYPTO_LIBS="-lgnutls"
			gnutls_found="yes"
			AC_MSG_NOTICE(libgnutls found in $d)
			break
		else
			AC_MSG_NOTICE(not found in $d)
		fi
	done

	if test x"$gnutls_found" != x"yes"
	then
		AC_MSG_ERROR([GnuTLS not found])
	fi
fi

if test x"$gnutls_found" = x"yes"
then
	AC_DEFINE(USE_GNUTLS, 1,
                  [Define to 1 to use libgnutls instead of OpenSSL.])

	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$LIBCRYPTO_CPPFLAGS $saved_CPPFLAGS"

	versioncheck='
		#include <gnutls/gnutls.h>

		#if GNUTLS_VERSION_NUMBER < 0x020b07
		# error GnuTLS 2.11.7 or later required
		#endif 
		int main()
		{
			return 0;
		}'

	AC_MSG_CHECKING([your GnuTLS version])
	AC_LINK_IFELSE([AC_LANG_SOURCE([$versioncheck])],
	               AC_MSG_RESULT(ok),
	               AC_MSG_FAILURE([GnuTLS must be at least version 2.11.7]))

	sha256check='
		#include <gnutls/gnutls.h>
		int main()
		{
			int x = GNUTLS_DIG_SHA256;
		}'

	AC_MSG_CHECKING([whether your GnuTLS supports SHA256])
	AC_LINK_IFELSE([AC_LANG_SOURCE([$sha256check])],
	               AC_MSG_RESULT(yes)
                       AC_DEFINE([HAVE_SHA256], 1,
 	                         [Define to 1 if your crypto library has SHA256 support]),
	               AC_MSG_WARN([SHA256 is required for DKIM but is not
	                            supported with your version of GnuTLS]))

	CPPFLAGS="$saved_CPPFLAGS"
fi

AM_CONDITIONAL([USE_GNUTLS], [test x"$gnutls_found" = x"yes"])

#
# OpenSSL
#

AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [location of OpenSSL includes and library]),
                           [sslpath="$withval"], [sslpath="auto"])

openssl_found="no"

if test x"$gnutls_found" = x"yes"
then
	sslpath="skip"
	openssl_found="skip"
fi

if test \( "$sslpath" = "auto" -o x"$sslpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([LIBCRYPTO], [openssl >= 0.9.7],
	                  [openssl_found="yes"],
	                  [openssl_found="no"
	                   AC_MSG_WARN([pkg-config for openssl not found, trying manual search...])
	                  ])
elif test "$sslpath" != "auto" -a x"$sslpath" != x"yes"
then
	AC_MSG_CHECKING([for OpenSSL includes])
	if test -f $sslpath/include/openssl/opensslconf.h
	then
		LIBCRYPTO_CPPFLAGS="-I$sslpath/include"
		LIBCRYPTO_CFLAGS=""
		LIBCRYPTO_LIBDIRS="-L$sslpath/lib"
		LIBCRYPTO_LIBS="-lssl -lcrypto"
		openssl_found=yes
		AC_MSG_RESULT([$sslpath])
	else
		AC_MSG_RESULT([no])
	fi
fi

if test x"$openssl_found" = x"no"
then
	AC_MSG_CHECKING([for OpenSSL library and includes])
	ssldirs="/usr/local/ssl /usr/local /usr/sfw /opt/local /usr"
	if test "$sslpath" = "auto" -o "$sslpath" = "yes"
	then
		for d in $ssldirs
		do
			if test -f $d/include/openssl/opensslconf.h
			then
				sslpath=$d
				openssl_found=yes
				break
			fi
		done
	fi
	case "$sslpath" in
		no)
			AC_MSG_ERROR([OpenSSL is required])
			;;
		auto)
			AC_MSG_ERROR([OpenSSL not found])
			;;
		*/*)
			AC_MSG_RESULT([$sslpath])
			;;
		*)
			AC_MSG_ERROR([OpenSSL not found])
			;;
	esac
        LIBCRYPTO_CPPFLAGS="-I$sslpath/include"
        LIBCRYPTO_CFLAGS=""
        LIBCRYPTO_LIBDIRS="-L$sslpath/lib"
        LIBCRYPTO_LIBS="-lssl -lcrypto"
fi

if test x"$openssl_found" = x"yes"
then
	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	LIBS="$LIBCRYPTO_LIBS $saved_LIBS"
	CPPFLAGS="$LIBCRYPTO_CPPFLAGS $saved_CPPFLAGS"
	CFLAGS="$LIBCRYPTO_CFLAGS $saved_CFLAGS"
	LDFLAGS="$LIBCRYPTO_LIBDIRS $saved_LDFLAGS"

	AC_CHECK_HEADERS([openssl/bio.h openssl/conf.h openssl/crypto.h openssl/err.h openssl/evp.h openssl/md5.h openssl/opensslv.h openssl/pem.h openssl/rsa.h openssl/sha.h openssl/ssl.h], ,
                 	AC_MSG_ERROR([required OpenSSL header not found]))

	# -ldl is needed to assist with compilation of static openssl libaries.
	# It appears to need dl for opening engine plugins. It fails at load
	# time It also fails to build on FreeBSD if enabled by default.
	AC_SEARCH_LIBS([ERR_peek_error], [crypto], ,
	               AC_MSG_ERROR([libcrypto not found]))

	AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
		[
			if test x"$enable_shared" = x"yes"
			then
				AC_MSG_ERROR([Cannot build shared opendkim
				              against static openssl libaries.
				              Configure with --disable-shared
				              to get this working or obtain a
				              shared libssl libary for
				              opendkim to use.])
			fi

			# avoid caching issue - last result of SSL_library_init
			# shouldn't be cached for this next check
			unset ac_cv_search_SSL_library_init
			LIBCRYPTO_LIBS="$LIBCRYPTO_LIBS -ldl"
			AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
			               AC_MSG_ERROR([libssl not found]), [-ldl])
		]
	)

	AC_CHECK_DECL([SHA256_DIGEST_LENGTH],
                      AC_DEFINE([HAVE_SHA256], 1,
 	                        [Define to 1 if your crypto library has SHA256 support]),
	              AC_MSG_WARN([SHA256 is required for DKIM but is not
	                           supported with your version of OpenSSL]),
	              [#include <openssl/sha.h>])

	CFLAGS="$saved_CFLAGS"
	CPPFLAGS="$saved_CPPFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi

AC_SUBST(LIBCRYPTO_CFLAGS)
AC_SUBST(LIBCRYPTO_CPPFLAGS)
AC_SUBST(LIBCRYPTO_LIBDIRS)
AC_SUBST(LIBCRYPTO_LIBS)

#
# libmilter
#
AC_MSG_CHECKING([for milter library and includes])
AC_ARG_WITH([milter],
            AS_HELP_STRING([--with-milter],
                           [location of milter includes and library]),
            [milterpath="$withval"], [milterpath="auto"])

if test x"$enable_filter" = x"no"
then
	milterpath="no"
fi

if test "$milterpath" = "auto" -o "$milterpath" = "yes"
then
	milterdirs="/usr/local /opt/local /usr"
	for d in $milterdirs
	do
		if test -f $d/include/libmilter/mfapi.h
		then
			milterpath=$d
			break
		fi
	done
fi
case "$milterpath" in
	no)
		if test x"$enable_filter" = x"yes"
		then
			AC_MSG_ERROR([milter is required])
		fi
		AC_MSG_RESULT(disabled)
		;;
	auto)
		AC_MSG_ERROR([milter not found])
		;;
	*/*)
		if ! test -f $milterpath/include/libmilter/mfapi.h
		then
			AC_MSG_ERROR([milter includes not found at $milterpath])
		fi
		AC_MSG_RESULT([$milterpath])
		;;
	*)
		AC_MSG_ERROR([milter not found])
		;;
esac

LIBMILTER_INCDIRS=""
LIBMILTER_LIBDIRS=""
LIBMILTER_LIBS=""

if test x"$milterpath" != x"no"
then
	LIBMILTER_INCDIRS="-I$milterpath/include"

	saved_CC="$CC"
	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	CC="$PTHREAD_CC"
	LIBS="$PTHREAD_LIBS $saved_LIBS"
	CPPFLAGS="$LIBMILTER_INCDIRS $saved_CPPFLAGS"
	CFLAGS="$PTHREAD_CFLAGS $saved_CFLAGS"
	LDFLAGS="$PTHREAD_CFLAGS $saved_LDFLAGS"

	breakloop="no"
	for d in lib lib/libmilter
	do
		unset ac_cv_search_smfi_register
		LDFLAGS="$PTHREAD_CFLAGS -L$milterpath/$d $saved_LDFLAGS"
		AC_SEARCH_LIBS([smfi_register], [milter],
		               [
		               	LIBMILTER_LIBDIRS="-L$milterpath/$d"
		               	LIBMILTER_LIBS="-lmilter"
		               	breakloop="yes"
		               ])

		AC_CHECK_FUNC([smfi_insheader],
			      AC_DEFINE([HAVE_SMFI_INSHEADER], 1,
					[Define if libmilter has smfi_insheader()]))

		AC_CHECK_FUNC([smfi_opensocket],
			      AC_DEFINE([HAVE_SMFI_OPENSOCKET], 1,
					[Define if libmilter has smfi_opensocket()]))

		AC_CHECK_FUNC([smfi_progress],
			      AC_DEFINE([HAVE_SMFI_PROGRESS], 1,
					[Define if libmilter has smfi_progress()]))

		AC_CHECK_FUNC([smfi_setsymlist],
			      AC_DEFINE([HAVE_SMFI_SETSYMLIST], 1,
					[Define if libmilter has smfi_setsymlist()]))

		AC_CHECK_FUNC([smfi_version],
			      AC_DEFINE([HAVE_SMFI_VERSION], 1,
					[Define if libmilter has smfi_version()]))

		if test x"$breakloop" = x"yes"
		then
			break
		fi
	done
	if test x"$LIBMILTER_LIBDIRS" = x""
	then
		AC_MSG_ERROR([libmilter not found])
	fi

	CC="$saved_CC"
	CPPFLAGS="$saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi

AC_SUBST(LIBMILTER_INCDIRS)
AC_SUBST(LIBMILTER_LIBDIRS)
AC_SUBST(LIBMILTER_LIBS)

#
# libmemcached
# 
AC_ARG_WITH([libmemcached],
            AS_HELP_STRING([--with-libmemcached],
                           [location of libmemcached includes and library]),
            [libmcdpath="$withval"], [libmcdpath="no"])

libmemcache_found="no"

if test \( x"$libmcdpath" = x"auto" -o x"$libmcdpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([LIBMEMCACHED], [libmemcached], 
	                  [
                          	libmemcache_found="yes"
	                  	LIBMEMCACHED_INCDIRS="$LIBMEMCACHED_CFLAGS"
	                  ],
	                  [
	                  	AC_MSG_WARN([pkg-config for libmemcached not found, trying manual search...])
	                  ])
fi

if test \( x"$libmcdpath" = x"auto" -o x"$libmcdpath" = x"yes" \) -a x"$libmemcache_found" = x"no"
then
	AC_MSG_CHECKING([for libmemcached])

	libmcddirs="/usr /usr/local"
	for d in $libmcddirs
	do
		if test -f $d/include/libmemcached/memcached.h
		then
			libmcdpath=$d
			AC_MSG_RESULT($d)
			LIBMEMCACHED_INCDIRS="-I$libmcdpath/include"
			LIBMEMCACHED_LIBDIRS="-L$libmcdpath/lib"
			LIBMEMCACHED_LIBS="-lmemcached"
			libmemcache_found="yes"
			break
		fi
	done
	if test x"$LIBMEMCACHED_LIBS" = x""
	then
		AC_MSG_ERROR([not found])
	fi
elif test x"$libmcdpath" != x"no" -a x"$libmemcache_found" = x"no"
then
	AC_MSG_CHECKING([for libmemcached])
	if test -f $libmcdpath/include/libmemcached/memcached.h
	then
		AC_MSG_RESULT([$libmcdpath])
		LIBMEMCACHED_INCDIRS="-I$libmcdpath/include"
		LIBMEMCACHED_LIBDIRS="-L$libmcdpath/lib"
		LIBMEMCACHED_LIBS="-lmemcached"
		libmemcache_found="yes"
	else
		AC_MSG_ERROR([not found at $libmcdpath])
	fi
fi

if test x"$libmcdpath" = x"no" -o x"$libmemcache_found" = x"no"
then
	LIBMEMCACHED_INCDIRS=""
	LIBMEMCACHED_LIBDIRS=""
	LIBMEMCACHED_LIBS=""
	AC_SUBST([LIBMEMCACHED_MANNOTICE],
	         "(Not enabled for this installation.)" )
else
	AC_DEFINE([USE_LIBMEMCACHED], 1,
	          [use memcache query library])
	AC_SUBST([LIBMEMCACHED_MANNOTICE], "" )
fi

AM_CONDITIONAL(USE_LIBMEMCACHED, test x"$libmcdpath" != x"no")
AC_SUBST(LIBMEMCACHED_INCDIRS)
AC_SUBST(LIBMEMCACHED_LIBDIRS)
AC_SUBST(LIBMEMCACHED_LIBS)

#
# libunbound
#
AC_ARG_WITH([unbound],
            AS_HELP_STRING([--with-unbound],
                           [location of Unbound includes and library]),
            [unboundpath="$withval"], [unboundpath="no"])

if test x"$unboundpath" != x"no" -a x"$enable_arlib" = x"yes"
then
	AC_MSG_ERROR([cannot use both arlib and unbound])
fi

if test x"$unboundpath" = x"yes"
then
	AC_MSG_CHECKING([for libunbound])

	unbounddirs="/usr /usr/local"
	for d in $unbounddirs
	do
		if test -f $d/include/unbound.h
		then
			unboundpath=$d
			AC_MSG_RESULT($d)
			LIBUNBOUND_INCDIRS="-I$unboundpath/include"
			LIBUNBOUND_LIBDIRS="-L$unboundpath/lib"
			LIBUNBOUND_LIBS="-lunbound"
			break
		fi
	done
	if test x"$LIBUNBOUND_LIBS" = x""
	then
		AC_MSG_ERROR([not found])
	fi
elif test x"$unboundpath" = x"no"
then
	LIBUNBOUND_INCDIRS=""
	LIBUNBOUND_LIBDIRS=""
	LIBUNBOUND_LIBS=""
else
	AC_MSG_CHECKING([for libunbound])
	if test -f $unboundpath/include/unbound.h
	then
		AC_MSG_RESULT([$unboundpath])
		LIBUNBOUND_INCDIRS="-I$unboundpath/include"
		LIBUNBOUND_LIBDIRS="-L$unboundpath/lib"
		LIBUNBOUND_LIBS="-lunbound"
	else
		AC_MSG_ERROR([not found at $unboundpath])
	fi
fi

if test x"$unboundpath" = x"no"
then
	AC_SUBST([UNBOUND_MANNOTICE], "(Not enabled for this installation.)" )
else
	AC_DEFINE([USE_UNBOUND], 1,
	          [use unbound DNSSEC libary for DNS])
	AC_SUBST([UNBOUND_MANNOTICE], "" )
fi

AM_CONDITIONAL(USE_UNBOUND, test x"$unboundpath" != x"no")
AC_SUBST(LIBUNBOUND_INCDIRS)
AC_SUBST(LIBUNBOUND_LIBDIRS)
AC_SUBST(LIBUNBOUND_LIBS)

# unbound also needs ldns
AC_ARG_WITH([ldns],
            AS_HELP_STRING([--with-ldns],
                           [location of ldns includes and library]),
            [ldnspath="$withval"], [ldnspath="no"])

LIBLDNS_LIBS=""
LIBLDNS_LIBDIRS=""

if test x"$ldnspath" = x"yes"
then
	ldns_found="no"

	AC_MSG_CHECKING([for libdns])

	ldnsdirs="/usr /usr/local"
	for d in $ldnsdirs
	do
		unset ac_cv_search_ldns_rr_new
		saved_LDFLAGS="$LDFLAGS"
		LDFLAGS="-L$d/lib $LDFLAGS"
		AC_SEARCH_LIBS([ldns_rr_new], [ldns], ldns_found="yes")
		LDFLAGS="$saved_LDFLAGS"

		if test x"$ldns_found" = x"yes"
		then
			LIBLDNS_LIBDIRS="-L$d/lib"
			LIBLDNS_LIBS="-lldns"
			AC_MSG_NOTICE(libldns found in $d)
			break
		fi
	done
	if test x"$LIBLDNS_LIBS" = x""
	then
		AC_MSG_ERROR([not found])
	fi
elif test x"$ldnspath" != x"no"
then
	AC_MSG_CHECKING([for libldns])
	ldns_found="no"
	saved_LDFLAGS="$LDFLAGS"
	LDFLAGS="-L$d/lib $LDFLAGS"
	AC_SEARCH_LIBS([ldns_rr_new], [ldns], ldns_found="yes")
	LDFLAGS="$saved_LDFLAGS"

	if test x"$ldns_found" = x"yes"
	then
		LIBLDNS_LIBDIRS="-L$d/lib"
		LIBLDNS_LIBS="-lldns"
		AC_MSG_NOTICE(libldns found in $d)
		break
	fi
fi

AC_SUBST(LIBLDNS_LIBDIRS)
AC_SUBST(LIBLDNS_LIBS)

#
# libtre
#
AC_ARG_WITH([tre],
            AS_HELP_STRING([--with-tre],
	                   [location of TRE includes and library]),
            [trepath="$withval"], [trepath="auto"])

tre_found="no"
LIBTRE_CFLAGS=""
LIBTRE_LIBS=""

if test x"$enable_diffheaders" != x"yes"
then
	trepath="no"
fi

if test \(  x"$trepath" = x"auto" -o x"$trepath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([LIBTRE], [tre >= 0.8.0], [tre_found="yes"],
	[
        	PKG_CHECK_MODULES([LIBTRE], [tre >= 0.7.5], 
		[
			tre_found="yes"
			AC_DEFINE([TRE_PRE_080], 1,
			          [version of libtre is older than 0.8.0])
		],[
		        tre_found="no"
        		AC_MSG_WARN([pkg-config for libtre >= 0.7.5 not found,
		             trying manual search...])
		])

        ])
fi

if test x"$tre_found" = x"no" -a x"$trepath" != x"no"
then
	AC_MSG_CHECKING([for libtre])
        if test x"$trepath" != x"auto" -a x"$trepath" != x"yes"
        then
                if test -f "$trepath/include/tre/tre.h"
                then
			tre_found="yes"
                        AC_MSG_RESULT($trepath)
                        LIBTRE_CFLAGS="-I$trepath/include"
                        LIBTRE_LIBS="-L$trepath/lib -ltre"
		elif test -f "$trepath/include/tre/regex.h"
		then
			tre_found="yes"
                        AC_MSG_RESULT([$trepath (old version)])
			AC_DEFINE([TRE_PRE_080], 1,
			          [version of libtre is older than 0.8.0])
                        LIBTRE_CFLAGS="-I$trepath/include"
                        LIBTRE_LIBS="-L$trepath/lib -ltre"
                else
                        AC_MSG_ERROR("not found at $trepath")
                fi
	else
		tredirs="/usr /usr/local"
		for d in $tredirs
		do
			if test -f $d/include/tre/tre.h
			then
				trepath=$d
				tre_found="yes"
				AC_MSG_RESULT($d)
				LIBTRE_CFLAGS="-I$trepath/include"
				LIBTRE_LIBS="-L$trepath/lib -ltre"
				break
			elif test -f $d/include/tre/regex.h
			then
				trepath=$d
				tre_found="yes"
				AC_MSG_RESULT([$d (old version)])
				AC_DEFINE([TRE_PRE_080], 1,
				          [version of libtre is older than 0.8.0])
				LIBTRE_CFLAGS="-I$trepath/include"
				LIBTRE_LIBS="-L$trepath/lib -ltre"
				break
			fi
		done
		if test x"$tre_found" != x"yes"
		then
			AC_MSG_RESULT([not found])
			AC_MSG_ERROR([cannot use diffheaders without TRE
			              library])
		fi
	fi
fi

if test x"$enable_diffheaders" = x"yes" -a x"$tre_found" = x"yes"
then
	AC_DEFINE([USE_TRE], 1, [tre regex library found])
fi

AM_CONDITIONAL([USE_TRE], [test x"$tre_found" != x"no"])
AC_SUBST([LIBTRE_CFLAGS])
AC_SUBST([LIBTRE_LIBS])

#
# liblua
#
AC_ARG_WITH(lua,
            AS_HELP_STRING([--with-lua],
                           [location of Lua includes and library]),
            [luapath="$withval"], [luapath="no"])

LIBLUA_INCDIRS=""
LIBLUA_LIBDIRS=""
LIBLUA_LIBS=""
lua_found="no"

if test \(  x"$luapath" = x"auto" -o x"$luapath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([LIBLUA], [lua >= 5.1.0],
	                  [
				lua_found="yes"
				LIBLUA_INCDIRS="$LIBLUA_CFLAGS"
	                  ],
	                  [AC_MSG_WARN([pkg-config for Lua not found, trying manual search...])])
fi

if test \( x"$luapath" = x"yes" -o x"$luapath" = x"auto" \) -a x"$lua_found" = x"no"
then
	AC_MSG_CHECKING([for Lua])
	luadirs="/usr /usr/local"
	for d in $luadirs
	do
		if test -f $d/include/lua51/lua.h
		then
			AC_MSG_RESULT($d)
			LIBLUA_INCDIRS="-I$d/include/lua51"
			LIBLUA_LIBDIRS="-L$d/lib/lua51"
			LIBLUA_LIBS="-llua -lm"
			AC_DEFINE([USE_LUA], 1,
			          [support for Lua scripting])
			AC_SUBST([LUA_MANNOTICE], "")
			lua_found="yes"
			break
		elif test -f $d/include/lua5.1/lua.h
		then
			AC_MSG_RESULT($d)
			LIBLUA_INCDIRS="-I$d/include/lua5.1"
			LIBLUA_LIBDIRS="-L$d/lib"
			LIBLUA_LIBS="-llua5.1 -lm"
			AC_DEFINE([USE_LUA], 1,
			          [support for Lua scripting])
			AC_SUBST([LUA_MANNOTICE], "")
			lua_found="yes"
			break
		elif test -f $d/include/lua.h
		then
			AC_MSG_RESULT($d)
			LIBLUA_INCDIRS="-I$d/include"
			LIBLUA_LIBDIRS="-L$d/lib"
			LIBLUA_LIBS="-llua -lm"
			lua_found="yes"
			break
		fi
	done
	if test x"$LIBLUA_LIBS" = x""
	then
		LIBLUA_INCDIRS=""
		LIBLUA_LIBDIRS=""
		LIBLUA_LIBS=""
		AC_MSG_ERROR(not found)
	else
		lua_found="yes"
	fi
fi

if test x"$luapath" != x"yes" -a x"$luapath" != x"auto" -a x"$luapath" != x"no"
then
	AC_MSG_CHECKING([for Lua])
	if test -f $luapath/include/lua51/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include/lua51"
		LIBLUA_LIBDIRS="-L$luapath/lib/lua51"
		LIBLUA_LIBS="-llua -lm"
		lua_found="yes"
	elif test -f $luapath/include/lua5.1/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include/lua5.1"
		LIBLUA_LIBDIRS="-L$luapath/lib"
		LIBLUA_LIBS="-llua5.1 -lm"
		lua_found="yes"
	elif test -f $luapath/include/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include"
		LIBLUA_LIBDIRS="-L$luapath/lib"
		LIBLUA_LIBS="-llua -lm"
		lua_found="yes"
	else
		AC_MSG_ERROR(not found at $luapath)
	fi
fi

if test x"$lua_found" = x"yes"
then
	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$LIBLUA_INCDIRS"
	AC_MSG_CHECKING([Lua version])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include <lua.h>

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 501
# error Lua version 5.1 or later is required
#endif

int
main()
{
	return 0;
}
				])],
				AC_MSG_RESULT([ok]), 
				AC_MSG_ERROR([Lua version 5.1 or later required]))
	CPPFLAGS="$saved_CPPFLAGS"
	AC_DEFINE([USE_LUA], 1, [support for Lua scripting])
	AC_SUBST([LUA_MANNOTICE], "")
else
	AC_SUBST([LUA_MANNOTICE], "(Not enabled for this installation.)")
fi

AM_CONDITIONAL(LUA, test x"$lua_found" = x"yes")
AC_SUBST(LIBLUA_INCDIRS)
AC_SUBST(LIBLUA_LIBDIRS)
AC_SUBST(LIBLUA_LIBS)

if test x"$enable_statsext" = x"yes" -a x"$lua_found" != x"yes"
then
	AC_MSG_ERROR([--enable-statsext requires Lua support])
fi

if test x"$enable_rbl" = x"yes" -a x"$lua_found" != x"yes"
then
	AC_MSG_ERROR([--enable-rbl requires Lua support])
fi

#
# libodbx
#
AC_ARG_WITH([odbx],
            AS_HELP_STRING([--with-odbx],
                           [location of OpenDBX includes and library]),
            [odbxpath="$withval"], [odbxpath="no"])

odbx_found="no"
LIBODBX_CPPFLAGS=""
LIBODBX_CFLAGS=""
LIBODBX_LIBS=""

if test \( x"$odbxpath" = x"auto" -o x"$odbxpath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([LIBODBX], [opendbx >= 1.3.7], [odbx_found="yes"],
	[
	        odbx_found="no"
        	AC_MSG_WARN([pkg-config for libodbx not found, trying manual
		            search...])
        ])
fi

if test x"$odbxpath" != x"no" -a x"$odbx_found" = x"no"
then
	saved_ldflags="$LDFLAGS"
	if test x"$odbxpath" != x"auto" -a x"$odbxpath" != x"yes"
	then
		if test -f $odbxpath/include/odbx.h
		then
			LDFLAGS="-L$odbxpath/lib"
			AC_CHECK_LIB(opendbx, odbx_result_finish,
			[
			        odbx_found="yes"
				LIBODBX_CPPFLAGS="-I$odbxpath/include"
				LIBODBX_LIBS="-L$odbxpath/lib -lopendbx"
			],
			[
				AC_MSG_ERROR([opendbx not at least v1.3.7 at $odbxpath])
			]
			)
		else
			AC_MSG_ERROR([opendbx not found at $odbxpath])
		fi
	else
		odbxdirs="/usr /usr/local"
		for d in $odbxdirs
		do
			if test -f $d/include/odbx.h
			then
				LDFLAGS="-L$d/lib"
				AC_CHECK_LIB(opendbx, odbx_result_finish,
				[
					odbxpath=$d
			        	odbx_found="yes"
					LIBODBX_CPPFLAGS="-I$odbxpath/include"
					LIBODBX_LIBS="-L$odbxpath/lib -lopendbx"
					break
				],[
					AC_MSG_ERROR([opendbx not at least v1.3.7 at $odbxpath])
				]
				)
			fi
		done
		if test x"$odbx_found" != x"yes"
		then
			AC_MSG_ERROR([opendbx not found])
		fi
	fi
	LDFLAGS="$saved_ldflags"
fi
if test x"$odbx_found" = x"yes"
then
	AC_DEFINE([USE_ODBX], 1, [ODBX support for datasets enabled])
else
	if test x"$enable_stats" = x"yes"
	then
		AC_MSG_WARN([opendbx is needed to import statistics into a SQL database - disabling opendkim-importstats])
	fi
fi
AM_CONDITIONAL(USE_ODBX, test x"$odbx_found" = x"yes")
AC_SUBST(LIBODBX_CPPFLAGS)
AC_SUBST(LIBODBX_CFLAGS)
AC_SUBST(LIBODBX_LIBS)

#
# OpenLDAP
#
AC_ARG_WITH([openldap],
            AS_HELP_STRING([--with-openldap],
                           [location of OpenLDAP includes and library]),
            [ldappath="$withval"], [ldappath="no"])

ldap_found="no"
OPENLDAP_CPPFLAGS=""
OPENLDAP_LIBS=""

if test \( x"$ldappath" = x"auto" -o x"$ldappath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([OPENLDAP], [openldap >= 2.0.0],
	[
		ldap_found="yes"
		OPENLDAP_CPPFLAGS="$OPENLDAP_CFLAGS"
	],
	[
	        ldap_found="no"
        	AC_MSG_WARN([pkg-config for openldap not found, trying manual
		            search...])
        ])
fi

if test x"$ldappath" != x"no" -a x"$ldap_found" = x"no"
then
	AC_MSG_CHECKING([for OpenLDAP])
	if test x"$ldappath" != x"auto" -a x"$ldappath" != x"yes"
	then
		if test -f $ldappath/include/ldap.h
		then
			AC_MSG_RESULT($ldappath)
		        ldap_found="yes"
			OPENLDAP_CPPFLAGS="-I$ldappath/include"
			OPENLDAP_LIBS="-L$ldappath/lib -lldap"
		else
			AC_MSG_ERROR(not found at $ldappath)
		fi
	else
		ldapdirs="/usr /usr/local"
		for d in $ldapdirs
		do
			if test -f $d/include/ldap.h
			then
				ldappath=$d
				AC_MSG_RESULT($d)
		        	ldap_found="yes"
				OPENLDAP_CPPFLAGS="-I$ldappath/include"
				OPENLDAP_LIBS="-L$ldappath/lib -lldap"
				break
			fi
		done
	fi
	if test x"$ldap_found" != x"yes"
	then
		AC_MSG_RESULT([no])
	fi
fi
if test x"$ldap_found" = x"yes"
then
	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$OPENLDAP_CPPFLAGS"
	AC_MSG_CHECKING([OpenLDAP version])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include <ldap.h>

#if !defined(LDAP_API_VERSION) || LDAP_API_VERSION < 2004
# error OpenLDAP version 2.1.3 or later is required
#endif

int
main()
{
	return 0;
}
				])],
				AC_MSG_RESULT([ok]), 
				AC_MSG_ERROR([OpenLDAP version 2.1.3 or later required]))
	CPPFLAGS="$saved_CPPFLAGS"
	AC_DEFINE([USE_LDAP], 1, [OpenLDAP support for datasets enabled])
fi
AM_CONDITIONAL(USE_LDAP, test x"$ldap_found" = x"yes")
AC_SUBST(OPENLDAP_CPPFLAGS)
AC_SUBST(OPENLDAP_LIBS)

#
# SASL
#
AC_ARG_WITH([sasl],
            AS_HELP_STRING([--with-sasl],
                           [location of SASL includes]),
            [saslpath="$withval"], [saslpath="auto"])
if test x"$ldap_found" != x"yes"
then
	# disable sasl if we don't have ldap
	saslpath="no"
fi

sasl_found="no"
if test \( x"$saslpath" = x"auto" -o x"$saslpath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([SASL], [cyrussasl >= 2.1.0],
	[
		sasl_found="yes"
		SASL_CPPFLAGS="$SASL_CFLAGS"
	],
	[
	        sasl_found="no"
        	AC_MSG_WARN([pkg-config for cyrussasl not found, trying manual
		            search...])
        ])
fi

if test x"$saslpath" != x"no" -a x"$sasl_found" = x"no"
then
	AC_MSG_CHECKING([for SASL])
	if test x"$saslpath" != x"auto" -a x"$saslpath" != x"yes"
	then
		if test -f $saslpath/include/sasl/sasl.h
		then
			AC_MSG_RESULT($saslpath)
		        sasl_found="yes"
			SASL_CPPFLAGS="-I$saslpath/include"
		else
			AC_MSG_ERROR(not found at $saslpath)
		fi
	else
		sasldirs="/usr /usr/local"
		for d in $sasldirs
		do
			if test -f $d/include/sasl/sasl.h
			then
				saslpath=$d
				AC_MSG_RESULT($d)
		        	sasl_found="yes"
				SASL_CPPFLAGS="-I$ldappath/include"
				break
			fi
		done
	fi
	if test x"$sasl_found" != x"yes"
	then
		AC_MSG_RESULT([no])
	fi
fi
if test x"$sasl_found" = x"yes"
then
	AC_DEFINE([USE_SASL], 1, [SASL support available])
fi
AM_CONDITIONAL(USE_SASL, test x"$sasl_found" = x"yes")
AC_SUBST(SASL_CPPFLAGS)

#
# libdb
#

AC_ARG_WITH([db-incdir],
            AS_HELP_STRING([--with-db-incdir],
                           [location of BerkeleyDB includes]),
            [bdb_incdir="$withval"], [bdb_incdir=""])

AC_ARG_WITH([db-libdir],
            AS_HELP_STRING([--with-db-libdir],
                           [location of BerkeleyDB library]),
            [bdb_libdir="$withval"], [bdb_libdir=""])

AC_ARG_WITH([db-lib],
            AS_HELP_STRING([--with-db-lib],
                           [name of BerkeleyDB library]),
            [bdb_lib="$withval"], [bdb_lib="db"])

AC_ARG_WITH([db],
            AS_HELP_STRING([--with-db],
                           [location of BerkeleyDB includes and library]),
            [bdb="$withval"], [bdb="auto"])

LIBDB_INCDIRS=""
LIBDB_LIBDIRS=""
LIBDB_LIBS=""

# was --with-db given with "yes" or a path?
bdbrequested="no"
if test x"$bdb" != x"no" -a x"$bdb" != x"auto"
then
	bdbrequested="yes"
fi
if test x"$bdb_incdir" != x"" -o x"$bdb_libdir" != x"" -o x"$bdb_lib" != x"db"
then
	bdbrequested="yes"
fi

AM_CONDITIONAL(USE_DB_OPENDKIM,
               test x"$enable_popauth" = x"yes" -o \
	            x"$enable_report_intervals" = x"yes" -o \
                    x"$bdbrequested" = x"yes")
AM_CONDITIONAL(USE_DB_LIBOPENDKIM, test x"$enable_query_cache" = x"yes")

# Is DB required based on --enables?
if test x"$USE_DB_OPENDKIM_TRUE" = x"" -o \
	x"$USE_DB_LIBOPENDKIM_TRUE" = x""
then
	bdbrequired="yes"
else
	bdbrequired="no"
fi

# If --with-db wasn't specified and the --enables demand it, force "yes"
if test x"$bdb" = x"auto"
then
	if test x"$bdbrequired" = x"yes"
	then
		bdb="yes"
	else
		bdb="no"
	fi
fi

if test x"$bdb" != x"yes" -a x"$bdb" != x"no"
then
	bdb_incdir=$bdb/include
	bdb_libdir=$bdb/lib
	bdb="yes"
fi

if test x"$bdb" = x"yes"
then
	bdbdirs="/usr/local/BerkeleyDB /usr/local /usr"
	libdbfound="no"

	# look for db.h
	AC_MSG_CHECKING([for BerkeleyDB db.h])
	if test x"$bdb_incdir" = x""
	then
		for d in $bdbdirs
		do
			if test -f $d/include/db.h
			then
				bdb_incdir=$d/include
				AC_MSG_RESULT($bdb_incdir)
				break
			fi
		done

		if test x"$bdb_incdir" = x""
		then
			AC_MSG_ERROR([not found])
		fi
	elif ! test -f $bdb_incdir/db.h
	then
		AC_MSG_ERROR([not found in $bdb_incdir])
	else
		AC_MSG_RESULT([$bdb_incdir])
	fi

	# look for libdb.a
	AC_MSG_CHECKING([for BerkeleyDB library lib$bdb_lib.a])
	if test x"$bdb_libdir" = x""
	then
		for d in $bdbdirs
		do
			if test -f $d/lib/lib$bdb_lib.a
			then
				bdb_libdir=$d/lib
				AC_MSG_RESULT($bdb_libdir)
				libdbfound="yes"
				break
			fi
		done

		if test x"$bdb_libdir" = x""
		then
			AC_MSG_RESULT([not found])
		fi
	elif ! test -f $bdb_libdir/lib$bdb_lib.a
	then
		AC_MSG_ERROR([not found in $bdb_libdir])
	else
		AC_MSG_RESULT([$bdb_libdir/lib$bdb_lib.a])
		libdbfound="yes"
	fi

	# If no matching library, see if we can find one.  Note that
	# this can cause compilation problems if for example a db.h
	# and a libdb are found that aren't the same version, but it's
	# worth a shot in general.
	if test x"$libdbfound" = x"no"
	then
		AC_SEARCH_LIBS([db_create], [db], [libdbfound="yes"])
	fi
	if test x"$libdbfound" = x"no"
	then
		AC_SEARCH_LIBS([dbopen], [db], [libdbfound="yes"])
	fi
	if test x"$libdbfound" = x"no"
	then
		AC_MSG_CHECKING([for libdb])
		for d in $bdbdirs
		do
			if test -f $d/lib/lib$bdb_lib.a
			then
				bdb_libdir=$d/lib
				AC_MSG_RESULT($bdb_libdir)
				libdbfound="yes"
				break
			fi
		done
	fi

	if test x"$libdbfound" = x"no"
	then
		AC_MSG_ERROR([cannot find db_create or dbopen])
	fi

	if test x"$bdb_incdir" != x""
	then
		LIBDB_INCDIRS="-I$bdb_incdir"
	fi
	if test x"$bdb_libdir" != x""
	then
		LIBDB_LIBDIRS="-L$bdb_libdir"
		LIBDB_LIBS="-l$bdb_lib"
	fi

	AC_DEFINE(USE_DB, 1,
	          [enable support for SleepyCat/Berkeley DB libraries])
elif test x"$bdb" = x"no"
then
	AC_MSG_CHECKING([for BerkeleyDB])
	if test x"$bdbrequired" = x"yes"
	then
		AC_MSG_ERROR([disabled but required by requested features])
	fi
	AC_MSG_RESULT([not required or disabled])
	LIBDB_INCDIRS=""
	LIBDB_LIBDIRS=""
	LIBDB_LIBS=""
fi

if test x"$unboundpath" != x"no" -a x"$bdbrequired" = x"yes"
then
	saved_LDFLAGS="$LDFLAGS"
	saved_CFLAGS="$CFLAGS"
	LDFLAGS="$LDFLAGS $LIBDB_LIBDIRS $LIBUNBOUND_LIBDIRS"
	CFLAGS="$CFLAGS $LIBDB_INCDIRS $LIBUNBOUND_INCDIRS"
	AC_CHECK_LIB([db],[log_file],
		AC_CHECK_LIB([unbound],[log_file],
			AC_MSG_ERROR([Cannot enable feature requiring BerkeleyDB with libunbound - both have log_file defined.  Please use newer BerkeleyDB version])
		)
	)
	LDFLAGS="$saved_LDFLAGS"
	CFLAGS="$saved_CFLAGS"
fi
AC_SUBST(LIBDB_INCDIRS)
AC_SUBST(LIBDB_LIBDIRS)
AC_SUBST(LIBDB_LIBS)

LIBOPENDKIM_LIBS="$LIBCRYPTO_LIBS $LIBTRE_LIBS $LIBRESOLV"
# This (below) is just for the pkg-config file opendkim.pc.in
LIBOPENDKIM_LIBS_PKG="$LIBOPENDKIM_LIBS"
LIBOPENDKIM_INC="$LIBCRYPTO_CPPFLAGS $LIBCRYPTO_CFLAGS $LIBTRE_CFLAGS"

if test x"$enable_arlib" = x"yes"
then
        # note this is just for PKG-CONFIG.
	LIBOPENDKIM_LIBS_PKG="$LIBOPENDKIM_LIBS_PKG -lar"
	# for Makefile
	LIBOPENDKIM_LIBS="$LIBOPENDKIM_LIBS ../libar/libar.la"
fi

if test x"$USE_DB_LIBOPENDKIM_TRUE" = x""
then
	LIBOPENDKIM_INC="$LIBOPENDKIM_INC $LIBDB_INCDIRS"
	LIBOPENDKIM_LIBS_PKG="$LIBOPENDKIM_LIBS_PKG $LIBDB_LIBS"
	LIBOPENDKIM_LIBS="$LIBOPENDKIM_LIBS $LIBDB_LIBS"
fi

AC_SUBST(LIBOPENDKIM_LIBS)
AC_SUBST(LIBOPENDKIM_LIBS_PKG)
AC_SUBST(LIBOPENDKIM_INC)

AC_DEFINE_UNQUOTED([LIBOPENDKIM_FEATURE_STRING], "$LIBOPENDKIM_FEATURE_STRING",
                   [Feature string for printing])

#
# setup for testing
# 

AC_ARG_ENABLE([live-testing],
              AS_HELP_STRING([--disable-live-testing],
                             [disable tests that require Internet access]),
              [live_tests="$enable_live_testing"], [live_tests="yes"])
AM_CONDITIONAL(LIVE_TESTS, test x"$live_tests" = x"yes")

#
# Platform Specific Configuration
#
AC_CANONICAL_HOST
case "$host" in
	*-darwin*)
		CPPFLAGS="$CPPFLAGS -DBIND_8_COMPAT"
		;;
esac

#
# Determine domainname for sample configs
#
AC_ARG_WITH([domain],
            AS_HELP_STRING([--with-domain],
                           [name of the domain for signing - sets this in sample configuration files]),
            [
                 DOMAIN="$withval"
	    ],[
                 AC_PATH_PROG(domainname, domainname)
	         AS_IF([test x"$domainname" != x""],
	         	[DOMAIN=`$domainname`],
		 )
		 AS_IF([test x"$DOMAIN" = x"" -o x"$DOMAIN" = x"(none)" ],
	         		[DOMAIN=example.com]
		 )
	    ]
	    )

AC_SUBST([DOMAIN])

#
# final command line tweaks
#

CPPFLAGS="$CPPFLAGS -DCONFIG_BASE=\\\"$sysconfdir\\\""

test "x$prefix" = xNONE && prefix=$ac_default_prefix 
SYSCONFDIR=`eval echo "$sysconfdir"`
AC_SUBST([SYSCONFDIR])

#
# Finish up
#
AC_OUTPUT([	Makefile
		docs/Makefile
		contrib/Makefile
			contrib/convert/Makefile
			contrib/init/Makefile
			contrib/init/generic/Makefile
			contrib/init/redhat/Makefile
			contrib/init/redhat/opendkim
			contrib/init/solaris/Makefile
			contrib/lua/Makefile
			contrib/spec/Makefile
			contrib/spec/opendkim.spec
			contrib/stats/Makefile
		libar/ar.pc libar/Makefile
		libar/tests/Makefile
		libdkimrep/dkim-rep.pc libdkimrep/Makefile
		libdkimrep/tests/Makefile
		libopendkim/opendkim.pc libopendkim/Makefile
		libopendkim/docs/Makefile
		libopendkim/tests/Makefile
		librbl/rbl.pc librbl/Makefile
		libvbr/vbr.pc libvbr/Makefile
		miltertest/Makefile
		opendkim/Makefile opendkim/opendkim.8 opendkim/opendkim-genkey
			opendkim/opendkim-genkey.8 opendkim/opendkim-genzone.8
			opendkim/opendkim-lua.3 opendkim/opendkim-testadsp.8
			opendkim/opendkim-testkey.8 opendkim/opendkim-stats.8
			opendkim/opendkim-testmsg.8 opendkim/opendkim.conf.5
			opendkim/opendkim.conf.simple
			opendkim/opendkim.conf.simple-verify
			opendkim/opendkim-atpszone.8 opendkim/opendkim-spam.1
		opendkim/tests/Makefile
		stats/Makefile stats/opendkim-anonstats.8
			stats/opendkim-importstats.8
])
