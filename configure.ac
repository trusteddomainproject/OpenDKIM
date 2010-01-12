#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# $Id: configure.ac,v 1.99.2.4 2010/01/12 08:52:33 cm-msk Exp $

#
# Setup
#
AC_PREREQ(2.62)

#
# Package version
#
m4_define([VERSION_RELEASE], 1)
m4_define([VERSION_MAJOR_REV], 3)
m4_define([VERSION_MINOR_REV], 0)
m4_define([VERSION_PATCH], 0)

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
ACX_PTHREAD

#
# Checks for libraries
#
AC_SEARCH_LIBS(inet_addr, nsl)
AC_SEARCH_LIBS(socket, socket)

AC_HEADER_RESOLV

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
AC_LINK_IFELSE([
$dnscheck
] , [
	AC_MSG_RESULT(yes)
	LIBRESOLV=
] , [
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([whether the resolver works with -lresolv])
	saved_LIBS="$LIBS"
	LIBS=-lresolv
	AC_LINK_IFELSE([
$dnscheck
	] , [
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
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h iso/limits_iso.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

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

#
# Checks for library functions.
#
AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strtol strtoul strtoull strlcpy strlcat])

#
# Library feature string and macros
#
LIBOPENDKIM_FEATURE_STRING="libopendkim $PACKAGE_VERSION:"

AC_DEFUN([TR_UP], [m4_translit([AS_TR_SH([$1])], [a-z], [A-Z])])

AC_DEFUN([FEATURE],
         [notincluded="(Not enabled in this installation.)"
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
         [experimentalnotincluded="(Experimental feature not enabled in this installation.)"
          AC_ARG_ENABLE($1, AS_HELP_STRING(--enable-$1, $2),
                        AS_IF([test "x$enable_]$1[" = "xyes"],
                              [
				AC_DEFINE([_FFR_]TR_UP($1), 1,
				          [enable $1 feature])
				AC_SUBST(TR_UP($1)[_MANNOTICE],
				         "(feature is experimental)")
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

FFR_FEATURE([bodylength_db], [support for body length DBs])

FFR_FEATURE([capture_unknown_errors],
            [quarantine unknown verification failures])

FFR_FEATURE([diffheaders], [compare signed and verified headers when possible])
LIB_FFR_FEATURE([diffheaders],
                [compare signed and verified headers when possible])

FFR_FEATURE([dkim_reputation], [experimental DKIM reputation checks])
LIB_FFR_FEATURE([dkim_reputation], [experimental DKIM reputation checks])

FFR_FEATURE([identity_header], [special header to set identity])

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

FFR_FEATURE([vbr], [Vouch-By-Reference support])
AM_CONDITIONAL([VBR], [test x"$enable_vbr" = x"yes"])

FFR_FEATURE([ztags], [sign/verify with z= tags])

FFR_FEATURE([stats], [stats recording and reporting])
AM_CONDITIONAL([STATS], [test x"$enable_stats" = x"yes"])

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
	if test x"$hasgcc" != x"yes" -a x"$hascc" = x"yes";
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
	        x"$hassuncc" = x"yes";
	then
		COV_CFLAGS="-g -xpg"
		COV_LDFLAGS="-g -xpg"
	# non-sun profiling
	elif test x"$hasgprof" = x"yes" -a \
		x"$hasgcov" != x"yes" -a \
		x"$hassuncc" != x"yes";
	then
		COV_CFLAGS="-g -pg"
		COV_LDFLAGS="-g -pg"
	# gcov profiling
	elif test x"$hasgcov" = x"yes";
	then
		COV_CFLAGS="-g -fprofile-arcs -ftest-coverage"
		COV_LIBADD="$GCOV_LIBS"
	fi

	AC_SUBST(COV_CFLAGS)
	AC_SUBST(COV_LDFLAGS)
	AC_SUBST(COV_LIBADD)
fi

AM_CONDITIONAL(LCOV, test x"$haslcov" = x"yes" -a x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV, test x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV_ONLY, test x"$hasgcov" = x"yes" -a x"$haslcov" != x"yes")
AM_CONDITIONAL(GPROF, test x"$hasgprof" = x"yes" -a x"$hasgcov" != x"yes")

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

LIB_FFR_FEATURE([dnsupgrade], [upgrade DNS to TCP when needed])
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
		LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING libar"
              ])
)

AM_CONDITIONAL([USE_ARLIB], [test x"$enable_arlib" = x"yes"])

AC_ARG_ENABLE([debug],
              AS_HELP_STRING([--enable-debug],
	                     [produce debugging binaries and libraries]),
              AS_IF([test "x$enable_debug" = "xyes"],
		[
			LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING debug"
			CFLAGS=`echo $CFLAGS | sed "s/ -O[0-9s]?//g"`
		])
)

AM_CONDITIONAL([DEBUG], [test "$enable_debug" = yes])

AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [location of OpenSSL includes and library]),
                           [sslpath="$withval"], [sslpath="auto"])

openssl_found="no"
if test \( "$sslpath" = "auto" -o x"$sslpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([LIBCRYPTO], [openssl >= 0.9.7],
	                  [openssl_found="yes"],
	                  [openssl_found="no"
	                   AC_MSG_WARN(["pkg-config for openssl not found, trying manual search..."])
	                  ])
fi

if test x"$openssl_found" = x"no"
then
	AC_MSG_CHECKING([for OpenSSL library and includes])
	ssldirs="/usr/local/ssl /usr/local /usr/sfw /usr"
	if test "$sslpath" = "auto" -o "$sslpath" = "yes"
	then
		for d in $ssldirs
		do
			if test -f $d/include/openssl/opensslconf.h
			then
				sslpath=$d
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
        LIBCRYPTO_CFLAGS="-I$sslpath/include"
        LIBCRYPTO_LIBDIRS="-L$sslpath/lib"
        LIBCRYPTO_LIBS="-lssl -lcrypto"
fi

saved_CFLAGS="$CFLAGS"
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
saved_LIBS="$LIBS"

LIBS="$LIBCRYPTO_LIBS $saved_LIBS"
CPPFLAGS="$LIBCRYPTO_CPPFLAGS $LIBCRYPTO_CFLAGS $saved_CPPFLAGS"
CFLAGS="$LIBCRYPTO_CFLAGS $saved_CFLAGS"
LDFLAGS="$LIBCRYPTO_LIBDIRS $saved_LDFLAGS"

AC_CHECK_HEADERS([openssl/bio.h openssl/conf.h openssl/crypto.h openssl/err.h openssl/evp.h openssl/md5.h openssl/opensslv.h openssl/pem.h openssl/rsa.h openssl/sha.h openssl/ssl.h], ,
                 AC_MSG_ERROR([required OpenSSL header not found]))

# -ldl is needed to assist with compilation of static openssl libaries.
# It appears to need dl for opening engine plugins. It fails at load time
# It also fails to build on FreeBSD if enabled by default.
AC_SEARCH_LIBS([ERR_peek_error], [crypto], ,
               AC_MSG_ERROR([libcrypto not found]))
AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
	[
		if test x"$enable_shared" = x"yes"
		then
			AC_MSG_ERROR([Cannot build shared opendkim against
			              static openssl libaries. Configure with
			              --disable-shared to get this working or
			              obtain a shared libssl libary for
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
AC_CHECK_DECL([SHA256_DIGEST_LENGTH], ,
              AC_MSG_WARN([SHA256 is required for DKIM but is not supported
                           with your version of OpenSSL]),
              [#include <openssl/sha.h>])

CFLAGS="$saved_CFLAGS"
CPPFLAGS="$saved_CPPFLAGS"
LDFLAGS="$saved_LDFLAGS"
LIBS="$saved_LIBS"

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
milterdirs="/usr/local /usr"
if test "$milterpath" = "auto" -o "$milterpath" = "yes"
then
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

LIBMILTER_INCDIRS="-I$milterpath/include"
LIBMILTER_LIBDIRS="-L$milterpath/lib"

saved_CFLAGS="$CFLAGS"
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
saved_LIBS="$LIBS"

CC="$PTHREAD_CC"
LIBS="$PTHREAD_LIBS $saved_LIBS"
CPPFLAGS="$LIBMILTER_INCDIRS $saved_CPPFLAGS"
CFLAGS="$PTHREAD_CFLAGS $saved_CFLAGS"
LDFLAGS="$PTHREAD_CFLAGS $LIBMILTER_LIBDIRS $saved_LDFLAGS"

AC_SEARCH_LIBS([smfi_register], [milter], ,
	[
		unset ac_cv_search_smfi_register
		LDFLAGS="$PTHREAD_CFLAGS -L$milterpath/lib $saved_LDFLAGS"
		AC_SEARCH_LIBS([smfi_register], [milter], ,
		               AC_MSG_ERROR([libmilter not found]))
	])

AC_CHECK_FUNC([smfi_setsymlist],
              AC_DEFINE([HAVE_SMFI_SETSYMLIST], 1,
                        [Define if libmilter has smfi_setsymlist()]))

CPPFLAGS="$saved_CPPFLAGS"
CFLAGS="$saved_CFLAGS"
LDFLAGS="$saved_LDFLAGS"
LIBS="$saved_LIBS"

AC_SUBST(LIBMILTER_INCDIRS)
AC_SUBST(LIBMILTER_LIBDIRS)

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
			break;
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
	AC_SUBST([UNBOUND_MANNOTICE], "(Not enabled in this installation.)" )
else
	AC_DEFINE([USE_UNBOUND], 1,
	          [use unbound DNSSEC libary for DNS])
	LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING unbound"
	AC_SUBST([UNBOUND_MANNOTICE], "" )
fi

AM_CONDITIONAL(USE_UNBOUND, test x"$unboundpath" != x"no")
AC_SUBST(LIBUNBOUND_INCDIRS)
AC_SUBST(LIBUNBOUND_LIBDIRS)
AC_SUBST(LIBUNBOUND_LIBS)

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
				break;
			elif test -f $d/include/tre/regex.h
			then
				trepath=$d
				tre_found="yes"
				AC_MSG_RESULT([$d (old version)])
				AC_DEFINE([TRE_PRE_080], 1,
				          [version of libtre is older than 0.8.0])
				LIBTRE_CFLAGS="-I$trepath/include"
				LIBTRE_LIBS="-L$trepath/lib -ltre"
				break;
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
# libodbx
#
AC_ARG_WITH([odbx],
            AS_HELP_STRING([--with-odbx],
                           [location of OpenDBX includes and library]),
            [odbxpath="$withval"], [odbxpath="no"])

odbx_found="no"
LIBODBX_CPPFLAGS=""
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
	AC_MSG_CHECKING([for OpenDBX])
	if test x"$odbxpath" != x"auto" -a x"$odbxpath" != x"yes"
	then
		if test -f $odbxpath/include/odbx.h
		then
			AC_MSG_RESULT($odbxpath)
		        odbx_found="yes"
			LIBODBX_CPPFLAGS="-I$odbxpath/include"
			LIBODBX_LIBS="-L$odbxpath/lib -lopendbx"
		else
			AC_MSG_ERROR(not found at $odbxpath)
		fi
	else
		odbxdirs="/usr /usr/local"
		for d in $odbxdirs
		do
			if test -f $d/include/odbx.h
			then
				odbxpath=$d
				AC_MSG_RESULT($d)
		        	odbx_found="yes"
				LIBODBX_CPPFLAGS="-I$odbxpath/include"
				LIBODBX_LIBS="-L$odbxpath/lib -lopendbx"
				break;
			fi
		done
	fi
	if test x"$odbx_found" = x"yes"
	then
		AC_MSG_RESULT([no])
	fi
fi
if test x"$odbx_found" = x"yes"
then
	AC_DEFINE([USE_ODBX], 1, [ODBX support for datasets enabled])
fi
AM_CONDITIONAL(USE_ODBX, test x"$odbx_found" = x"yes")
AC_SUBST(LIBODBX_CPPFLAGS)
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
        PKG_CHECK_MODULES([OPENLDAP], [openldap >= 2.0.0], [ldap_found="yes"],
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
				break;
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
            [saslpath="$withval"], [saslpath="no"])
if test x"$ldap_found" = x"yes" -a x"$saslpath" = x"no"
then
	saslpath="auto"
fi

sasl_found="no"
if test \( x"$saslpath" = x"auto" -o x"$saslpath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([CYRUSSASL], [cyrussasl >= 2.1.0], [sasl_found="yes"],
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
				break;
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
bdb="no"
AC_ARG_WITH([db],
            AS_HELP_STRING([--with-db],
                           [location of BerkeleyDB includes and library]),
            [bdb="$withval"], [bdb="auto"])

LIBDB_INCDIRS=""
LIBDB_LIBDIRS=""
LIBDB_LIBS=""

AM_CONDITIONAL(USE_DB_OPENDKIM,
               test x"$enable_bodylengthdb" = x"yes" -o \
	            x"$enable_popauth" = x"yes" -o \
	            x"$enable_stats" = x"yes" -o \
	            x"$enable_report_intervals" = x"yes" -o \
                    x"$bdb" != x"no")
AM_CONDITIONAL(USE_DB_LIBOPENDKIM, test x"$enable_query_cache" = x"yes")

if test x"$USE_DB_OPENDKIM_TRUE" = x"" -o \
	x"$USE_DB_LIBOPENDKIM_TRUE" = x""
then
	bdbrequired="yes"
else
	bdbrequired="no"
fi

if test x"$bdb" = x"auto"
then
	if test x"$bdbrequired" = x"yes"
	then
		bdb="yes"
	else
		bdb="no"
	fi
fi

if test x"$bdb" = x"yes"
then
	AC_MSG_CHECKING([for BerkeleyDB])

	bdbdirs="/usr/local/BerkeleyDB /usr/local /usr"
	libdbfound="no"

	# first look for db.h
	for d in $bdbdirs
	do
		if test -f $d/include/db.h
		then
			bdb=$d
			AC_MSG_RESULT($d)
			LIBDB_INCDIRS="-I$bdb/include"
			break;
		fi
	done

	# yes here means the above look didn't find it
	if test x"$bdb" = x"yes"
	then
		AC_MSG_ERROR([db.h not found])
	fi

	# found db.h, see if there's a matching library
	AC_MSG_CHECKING(for libdb in $bdb)
	if test -f $bdb/lib/libdb.a
	then
		libdbfound="yes"
		AC_MSG_RESULT([found])
		LIBDB_LIBDIRS="-L$bdb/lib"
		LIBDB_LIBS="-ldb"
	else
		AC_MSG_RESULT([not found])
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
			if test -f $d/lib/libdb.a
			then
				bdb=$d
				AC_MSG_RESULT($d)
				LIBDB_LIBDIRS="-L$bdb/lib"
				LIBDB_LIBS="-ldb"
				libdbfound="yes"
				break;
			fi
		done
	fi

	if test x"$libdbfound" = "xno"
	then
		AC_MSG_ERROR([cannot find db_create or dbopen])
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
else
	AC_MSG_CHECKING([for db.h])

	if test -f $bdb/include/db.h
	then
		LIBDB_INCDIRS="-I$bdb/include"
		AC_MSG_RESULT([$bdb])
	else
		AC_MSG_ERROR([not found at $bdb])
	fi

	# we might not need -ldb if DB is built into libc
	AC_MSG_CHECKING([for libdb])
 	if test -f $bdb/lib/libdb.a
	then
		LIBDB_LIBDIRS="-L$bdb/lib"
		LIBDB_LIBS="-ldb"
		AC_MSG_RESULT([$bdb])
		AC_DEFINE(USE_DB, 1,
		          [enable support for SleepyCat/Berkeley DB libraries])
	else
		AC_MSG_RESULT([not found - assuming libc])
		AC_DEFINE(USE_DB, 1,
		          [enable support for SleepyCat/Berkeley DB libraries])
	fi
fi

AC_SUBST(LIBDB_INCDIRS)
AC_SUBST(LIBDB_LIBDIRS)
AC_SUBST(LIBDB_LIBS)

#
# libdk
#
AC_ARG_WITH([domainkeys],
            AS_HELP_STRING([--with-domainkeys],
                           [location of libdk includes and library]),
            [dk="$withval"], [dk="no"])

if test x"$dk" = x"yes"
then
	AC_MSG_CHECKING([for DomainKeys])

	dkdirs="/usr /usr/local"
	for d in $dkdirs
	do
		if test -f $d/include/dk.h -a -f $d/lib/libdk.a
		then
			dk=$d
			AC_MSG_RESULT([$d])
			LIBDK_INCDIRS="-I$dk/include"
			LIBDK_LIBDIRS="-L$dk/lib"
			LIBDK_LIBS="-ldk"
			AC_DEFINE([VERIFY_DOMAINKEYS], 1,
			          [compile with libdk for DomainKeys support])
			break;
		fi
	done

	if test x"$dk" = x"yes"
	then
		AC_MSG_ERROR([not found])
	fi
elif test x"$dk" = x"no"
then
	LIBDK_INCDIRS=""
	LIBDK_LIBDIRS=""
	LIBDK_LIBS=""
else
	AC_MSG_CHECKING([for DomainKeys])

	if test -f $d/include/dk.h -a -f $d/lib/libdk.a
	then
		AC_MSG_RESULT($dk)
		LIBDK_INCDIRS="-I$dk/include"
		LIBDK_LIBDIRS="-L$dk/lib"
		LIBDK_LIBS="-ldk"
		AC_DEFINE([VERIFY_DOMAINKEYS], 1,
		          [compile with libdk for DomainKeys support])
	else
		AC_MSG_ERROR([not found at $dk])
	fi
fi

liBOPENDKIM_LIBS="$LIBCRYPTO_LIBS $LIBTRE_LIBS $LIBUNBOUND_LIBS $LIBDK_LIBS $LIBRESOLV"
# This (below) is just for the pkg-config file opendkim.pc.in
LIBOPENDKIM_LIBS_PKG="$LIBOPENDKIM_LIBS"
LIBOPENDKIM_INC="$LIBCRYPTO_CPPFLAGS $LIBCRYPTO_CFLAGS $LIBTRE_CFLAGS $LIBUNBOUND_INCDIRS $LIBDK_INCDIRS"

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

AM_CONDITIONAL(VERIFY_DOMAINKEYS, test x"$dk" != x"no")

AC_DEFINE_UNQUOTED([LIBOPENDKIM_FEATURE_STRING], "$LIBOPENDKIM_FEATURE_STRING",
                   [Feature string for printing])

#
# Finish up
#
AC_OUTPUT([Makefile opendkim/Makefile libopendkim/Makefile libar/Makefile
           libopendkim/tests/Makefile libvbr/Makefile libopendkim/opendkim.pc
           libar/ar.pc libvbr/vbr.pc
           opendkim/opendkim.conf.5 opendkim/opendkim.8
           opendkim/opendkim-testkey.8 opendkim/opendkim-stats.8
           opendkim/opendkim-genkey.8 opendkim/opendkim-testadsp.8])
