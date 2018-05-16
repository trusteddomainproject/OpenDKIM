#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
# 

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 2)
m4_define([VERSION_MAJOR_REV], 11)
m4_define([VERSION_MINOR_REV], 0)
m4_define([VERSION_PATCH], 0)

#
# Library version
# 	- bump "current" and reset "revision" with API changes
# 	- bump "revision" with internal source code changes
#
m4_define([LIBVERSION_CURRENT], 11)
m4_define([LIBVERSION_REVISION], 0)
m4_define([LIBVERSION_AGE], 0)

#
# Autotools setup
#
AC_INIT([OpenDKIM],
        [VERSION_RELEASE.VERSION_MAJOR_REV.VERSION_MINOR_REV],
        [bugs@opendkim.org])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE(
  1.11.1
  dnl Automake version before 1.13 (when the serial-tests option was
  dnl still the default) still defined the badly obsolete macro
  dnl 'AM_PROG_INSTALL'.
  m4_ifndef([AM_PROG_INSTALL], [serial-tests])
)
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
# save outer values
#
outer_CFLAGS="$CFLAGS"
outer_CPPFLAGS="$CPPFLAGS"
outer_LDFLAGS="$LDFLAGS"
outer_LIBS="$LIBS"

#
# Checks for libraries
#
saved_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS(inet_addr, nsl)
LIBNSL_LIBS="$LIBS"
LIBS="$saved_LIBS"
AC_SUBST([LIBNSL_LIBS])

saved_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS(dlopen, dl)
LIBDL_LIBS="$LIBS"
LIBS="$saved_LIBS"
AC_SUBST([LIBDL_LIBS])

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_SEARCH_LIBS(inet_pton, resolv,
               AC_DEFINE(HAVE_INET_PTON, 1,
                         [Define to 1 if you have the `inet_pton()' function.]))
AC_SEARCH_LIBS(inet_ntop, resolv nsl,
               AC_DEFINE(HAVE_INET_NTOP, 1,
                        [Define to 1 if you have the `inet_ntop()' function.]))
AC_SEARCH_LIBS(getaddrinfo, resolv,
               AC_DEFINE(HAVE_GETADDRINFO, 1,
                         [Define to 1 if you have the `getaddrinfo()' function.]))
AC_SEARCH_LIBS(res_ninit, resolv,
               AC_DEFINE(HAVE_RES_NINIT, 1,
                         [Define to 1 if you have the `res_ninit()' function.]))
AC_SEARCH_LIBS(res_sertservers, resolv bind,
               AC_DEFINE(HAVE_RES_SETSERVERS, 1,
                         [Define to 1 if you have the `res_setservers()' function.]))
AC_SEARCH_LIBS(getopt_long, iberty,
               AC_DEFINE(HAVE_GETOPT_LONG, 1,
                         [Define to 1 if you have the `getopt_long()' function.]))

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
LIBRESOLV=
AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
])] , [
	AC_MSG_RESULT(yes)
] , [
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([whether the resolver works with -lresolv])
	saved_LIBS="$LIBS"
	LIBS="$outer_LIBS -lresolv"
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

AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gethostbyname getaddrinfo gethostbyname2 gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul strtoull realpath strsep])

bsdstrl_h_found="no"
strl_found="no"
libstrl_found="no"
strl_h_found="no"

AC_CHECK_HEADERS([bsd/string.h], [bsdstrl_h_found="yes"])

AC_CHECK_FUNCS([strlcat strlcpy], [strl_found="yes"],
               [
		saved_LIBS="$LIBS"
		LIBS="$outer_LIBS"
		AC_SEARCH_LIBS([strlcat],
		               [bsd strl],
		               [libstrl_found="yes"],
		               [strl_found="no"])
		AC_SEARCH_LIBS([strlcpy],
		               [bsd strl],
		               [libstrl_found="yes"],
		               [strl_found="no"])
		STRL_LIBS="$LIBS"
		LIBS="$saved_LIBS"
               ])

if test x"$libstrl_found" = x"yes"
then
	LIBS="$LIBS $STRL_LIBS"
fi

# we need something above to have worked
if test x"$strl_found" != x"yes" -a x"$libstrl_found" != x"yes"
then
	AC_MSG_ERROR(no strlcpy/strlcat found)
fi

AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
if test x"$strl_h_found" != x"yes"
then
	strldirs="/usr/local/include/strl /usr/local/include /usr/include/strl"

	for d in $strldirs
	do
		AC_MSG_CHECKING([for strl.h in $d])
		if test -f $d/strl.h
		then
			unset ac_cv_header_strl_h
			saved_CPPFLAGS="$CPPFLAGS"
			CPPFLAGS="$CPPFLAGS -I$d"
			AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
			CPPFLAGS="$saved_CPPFLAGS"
		fi

		if test x"$strl_h_found" = x"yes"
		then
			CPPFLAGS="$CPPFLAGS -I$d"
			break
		fi
	done
fi

# we need to include <strl.h> if an installed strl.h was found and no
# bsd/string.h was found
if test x"$strl_h_found" = x"yes" -a x"$bsdstrl_h_found" = x"no"
then
	AC_DEFINE([USE_STRL_H], 1,
	          [Define to 1 if you need to include <strl.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

if test x"$bsdstrl_h_found" = x"yes"
then
	AC_DEFINE([USE_BSD_H], 1,
	          [Define to 1 if you need to include <bsd/string.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

#
# Checks for structure members
#
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
                AC_DEFINE([HAVE_SUN_LEN],
                          [1],
                          [Define if sockaddr_un has a sun_len member]),
                [],
                [[#include <sys/un.h>]])

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
                AC_DEFINE([HAVE_SIN_LEN],
                          [1],
                          [Define if sockaddr_in has a sin_len member]),
                [],
                [[#include <netinet/in.h>]])

AC_CHECK_MEMBER([struct sockaddr_in6.sin6_len],
                AC_DEFINE([HAVE_SIN6_LEN],
                          [1],
                          [Define if sockaddr_in6 has a sin6_len member]),
                [],
                [[#include <netinet/in.h>]])

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

FFR_FEATURE([conditional], [experimental conditional signatures])
LIB_FFR_FEATURE([conditional], [experimental conditional signatures])
AM_CONDITIONAL([CONDITIONAL], [test x"$enable_conditional" = x"yes"])

FFR_FEATURE([db_handle_pools], [experimental database handle pools])

FFR_FEATURE([diffheaders], [compare signed and verified headers when possible])
LIB_FFR_FEATURE([diffheaders],
                [compare signed and verified headers when possible])

FFR_FEATURE([identity_header], [special header to set identity])

FFR_FEATURE([ldap_caching], [LDAP query piggybacking and caching])

FFR_FEATURE([postgresql_reconnect_hack],
            [hack to overcome PostgreSQL connection error detection bug])

FFR_FEATURE([rate_limit], [support for DKIM-based rate limiting])

FFR_FEATURE([replace_rules], [support for string substitution when signing])
AM_CONDITIONAL([REPLACE_RULES], [test x"$enable_replace_rules" = x"yes"])

FFR_FEATURE([reprrd],
            [support for experimental reputation checks using RRD])
AM_CONDITIONAL([REPRRD], [test x"$enable_reprrd" = x"yes"])
AC_CHECK_PROG([hasrrdtool], [rrdtool], [yes])
if test x"$enable_reprrd" = x"yes" -a x"$hasrrdtool" != x"yes"
then
	AC_MSG_ERROR([--enable-reprrd requires rrdtool binary, not found])
fi

FFR_FEATURE([reputation],
            [support for experimental reputation checks])
if test x"$enable_reputation" = x"yes"
then
	AC_SEARCH_LIBS([ceil], [m])
fi
AM_CONDITIONAL([REPUTE], [test x"$enable_reputation" = x"yes"])

FFR_FEATURE([resign],
            [support for one-step re-signing])

FFR_FEATURE([sender_macro], [macro to determine sender])

FFR_FEATURE([socketdb], [arbitrary socket data sets])

FFR_FEATURE([stats], [stats recording and reporting])
AM_CONDITIONAL([STATS], [test x"$enable_stats" = x"yes"])
FFR_FEATURE([statsext], [extended stats recording and reporting])

FFR_FEATURE([rbl], [Realtime Blacklist query support])
AM_CONDITIONAL([RBL], [test x"$enable_rbl" = x"yes"])

FFR_FEATURE([vbr], [Vouch-By-Reference support])
AM_CONDITIONAL([VBR], [test x"$enable_vbr" = x"yes"])

if test x"$enable_statsext" = x"yes" -a x"$enable_stats" != x"yes"
then
	AC_MSG_ERROR([--enable-statsext requires --enable-stats])
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

AC_ARG_ENABLE(
	[rpath],
	AS_HELP_STRING([--enable-rpath],
	               [include library load paths in binaries]),
	,
	enable_rpath="yes")
AM_CONDITIONAL([RPATH], [test x"$enable_rpath" = x"yes"])
if test x"$enable_rpath" != x"yes"
then
	AC_MSG_RESULT([Suppressing -rpath use by libtool])
	hardcode_libdir_flag_spec=" -D__LIBTOOL_NO_RPATH__ "
	chmod 0755 libtool
fi

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
		LIBS="$outer_LIBS"
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
LIB_FEATURE([query_cache], [local key caching])

#
# Conditional stuff
#
AC_ARG_ENABLE([allsymbols],
              AS_HELP_STRING([--enable-allsymbols],
                             [export internal-use symbols for better test coverage]))
AM_CONDITIONAL(ALL_SYMBOLS, [test x"$enable_allsymbols" = x"yes"])

# the AM_CONDITIONAL and AC_DEFINE for USE_ARLIB are farther below,
# after the Darwin checks

AC_ARG_ENABLE([debug],
              AS_HELP_STRING([--enable-debug],
	                     [produce debugging binaries and libraries]),
              AS_IF([test "x$enable_debug" = x"yes"],
		[
			LIBOPENDKIM_FEATURE_STRING="$LIBOPENDKIM_FEATURE_STRING debug"
			[[CFLAGS=`echo $CFLAGS | sed 's/ -O[1-9s]*//g'`]]
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
	PKG_CHECK_MODULES([GNUTLS], [gnutls >= 2.11.7],
	                  [gnutls_found="pkg-config"],
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

	LIBS="$outer_LIBS -lgnutls $saved_LIBS"
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

if test x"$gnutls_found" = x"pkg-config"
then
	LIBCRYPTO_CPPFLAGS="$GNUTLS_CFLAGS"
	LIBCRYPTO_LDFLAGS=""
	LIBCRYPTO_LIBS="$GNUTLS_LIBS"
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

		LIBS="$outer_LIBS -lgnutls $saved_LIBS"
		CPPFLAGS="-I$d/include $saved_CPPFLAGS"
		CFLAGS="$saved_CFLAGS"
		LDFLAGS="$outer_LDFLAGS -L$d/lib $saved_LDFLAGS"

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
	if test -f $sslpath/include/openssl/opensslv.h
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
			if test -f $d/include/openssl/opensslv.h
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

	LIBS="$outer_LIBS $LIBCRYPTO_LIBS $saved_LIBS"
	CPPFLAGS="$LIBCRYPTO_CPPFLAGS $saved_CPPFLAGS"
	CFLAGS="$LIBCRYPTO_CFLAGS $saved_CFLAGS"
	LDFLAGS="$outer_LDFLAGS $LIBCRYPTO_LIBDIRS $saved_LDFLAGS"

	AC_CHECK_HEADERS([openssl/bio.h openssl/conf.h openssl/crypto.h openssl/err.h openssl/evp.h openssl/md5.h openssl/opensslv.h openssl/pem.h openssl/rsa.h openssl/sha.h openssl/ssl.h], ,
                 	AC_MSG_ERROR([required OpenSSL header not found]))

	# -ldl is needed to assist with compilation of static openssl libraries.
	# It appears to need dl for opening engine plugins. It fails at load
	# time It also fails to build on FreeBSD if enabled by default.
	AC_SEARCH_LIBS([ERR_peek_error], [crypto], ,
	               AC_MSG_ERROR([libcrypto not found]))


	AC_LINK_IFELSE(
		       [AC_LANG_PROGRAM([[#include <openssl/ssl.h>]],
					[[SSL_library_init();]])],
					[od_have_ossl="yes";],
					[od_have_ossl="no";])
	if test x"$od_have_ossl" = x"no"
	then
		if test x"$enable_shared" = x"yes"
		then
			AC_MSG_ERROR([Cannot build shared opendkim
			              against static openssl libraries.
			              Configure with --disable-shared
			              to get this working or obtain a
			              shared libssl library for
			              opendkim to use.])
		fi

		LIBCRYPTO_LIBS="$LIBCRYPTO_LIBS -ldl"
		AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
		               AC_MSG_ERROR([libssl not found]), [-ldl])
	fi

	AC_CHECK_DECL([EVP_PKEY_ED25519],
                      AC_DEFINE([HAVE_ED25519], 1,
 	                        [Define to 1 if your crypto library has ED25519 support]), ,
	              [
#include <sys/types.h>
#include <openssl/evp.h>])

	AC_CHECK_DECL([SHA256_DIGEST_LENGTH],
                      AC_DEFINE([HAVE_SHA256], 1,
 	                        [Define to 1 if your crypto library has SHA256 support]),
	              AC_MSG_WARN([SHA256 is required for DKIM but is not
	                           supported with your version of OpenSSL]),
	              [
#include <sys/types.h>
#include <openssl/sha.h>])

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
	LIBS="$outer_LIBS $PTHREAD_LIBS $saved_LIBS"
	CPPFLAGS="$LIBMILTER_INCDIRS $saved_CPPFLAGS"
	CFLAGS="$PTHREAD_CFLAGS $saved_CFLAGS"
	LDFLAGS="$outer_LDFLAGS $PTHREAD_CFLAGS $saved_LDFLAGS"

	breakloop="no"
	for d in lib lib64 lib/libmilter
	do
		unset ac_cv_search_smfi_register
		LDFLAGS="$outer_LDFLAGS $PTHREAD_CFLAGS -L$milterpath/$d $saved_LDFLAGS"
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
# librrd
# 
AC_ARG_WITH([librrd],
            AS_HELP_STRING([--with-librrd],
                           [location of librrd includes and library]),
            [librrdpath="$withval"], [librrdpath="no"])

librrd_found="no"
if test x"$enable_reprrd" = x"yes" -a x"$librrdpath" = x"no"
then
	librrdpath="auto"
fi

if test \( x"$librrdpath" = x"auto" -o x"$librrdpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([RRDTOOL], [librrd], 
	                  [
                          	librrd_found="yes"
	                  ],
	                  [
	                  	AC_MSG_WARN([pkg-config for rrdtool not found, trying manual search...])
	                  ])
fi

if test \( x"$librrdpath" = x"auto" -o x"$librrdpath" = x"yes" \) -a x"$librrd_found" = x"no"
then
	AC_MSG_CHECKING([for librrd])

	librrddirs="/usr /usr/local"
	for d in $librrddirs
	do
		if test -f $d/include/rrd.h
		then
			librrdpath=$d
			AC_MSG_RESULT($d)
			RRDTOOL_CFLAGS="-I$librrdpath/include"
			RRDTOOL_LIBS="-L$librrdpath/lib -lrrd"
			librrd_found="yes"
			break
		fi
	done
	if test x"$RRDTOOL_LIBS" = x""
	then
		AC_MSG_ERROR([not found])
	fi
elif test x"$librrdpath" != x"no" -a x"$librrd_found" = x"no"
then
	AC_MSG_CHECKING([for librrd])
	if test -f $librrdpath/include/rrd.h
	then
		AC_MSG_RESULT([$librrdpath])
		RRDTOOL_CFLAGS="-I$librrdpath/include"
		RRDTOOL_LIBS="-L$librrdpath/lib -lrrd"
		librrd_found="yes"
	else
		AC_MSG_ERROR([not found at $librrdpath])
	fi
fi

if test x"$librrdpath" = x"no" -o x"$librrd_found" = x"no"
then
	RRDTOOL_CFLAGS=""
	RRDTOOL_LIBS=""
	AC_SUBST([LIBRRD_MANNOTICE],
	         "(Not enabled for this installation.)" )
else
	AC_DEFINE([USE_RRD], 1,
	          [use RRD library])
	AC_SUBST([LIBRRD_MANNOTICE], "" )
fi

AM_CONDITIONAL(USE_RRD, test x"$librrdpath" != x"no")
AC_SUBST(RRDTOOL_CFLAGS)
AC_SUBST(RRDTOOL_LIBS)

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
	PKG_CHECK_MODULES([LIBMEMCACHED], [libmemcached >= 0.36], 
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

# confirm memcached_return_t is defined
if test x"$libmemcache_found" = x"yes"
then
	saved_CPPFLAGS=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $LIBMEMCACHED_INCDIRS"
	AC_MSG_CHECKING([for memcached_return_t])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#include <libmemcached/memcached.h>

int
main()
{
	memcached_return_t x;

	return 0;
}
		])],
		AC_MSG_RESULT([ok]), 
		AC_MSG_ERROR([libmemcached version 0.36 or later required]))
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
	          [use unbound DNSSEC library for DNS])
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

	ldnsdirs="/usr /usr/local"
	for d in $ldnsdirs
	do
		unset ac_cv_search_ldns_rr_new
		saved_LDFLAGS="$LDFLAGS"
		saved_LIBS="$LIBS"
		LDFLAGS="$outer_LDFLAGS -L$d/lib $LDFLAGS"
		LIBS="$outer_LIBS"
		AC_SEARCH_LIBS([ldns_rr_new], [ldns], ldns_found="yes")
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$saved_LIBS"

		if test x"$ldns_found" = x"yes"
		then
			LIBLDNS_LIBDIRS="-L$d/lib"
			LIBLDNS_LIBS="-lldns"
			break
		fi
	done
	if test x"$LIBLDNS_LIBS" = x""
	then
		AC_MSG_ERROR([libldns not found])
	fi
elif test x"$ldnspath" != x"no"
then
	ldns_found="no"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"
	LDFLAGS="$outer_LDFLAGS -L$d/lib $LDFLAGS"
	LIBS="$outer_LIBS"
	AC_SEARCH_LIBS([ldns_rr_new], [ldns], ldns_found="yes")
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"

	if test x"$ldns_found" = x"yes"
	then
		LIBLDNS_LIBDIRS="-L$d/lib"
		LIBLDNS_LIBS="-lldns"
		break
	else
		AC_MSG_ERROR(libldns not found in $d)
	fi
fi

AC_SUBST(LIBLDNS_LIBDIRS)
AC_SUBST(LIBLDNS_LIBS)

# unbound may also need libevent
AC_ARG_WITH([libevent],
            AS_HELP_STRING([--with-libevent],
                           [location of libevent includes and library]),
            [libeventpath="$withval"], [libeventpath="no"])

LIBEVENT_LIBS=""
LIBEVENT_LIBDIRS=""

if test x"$libevent" = x"yes"
then
	libevent_found="no"

	libeventdirs="/usr /usr/local"
	for d in $libeventdirs
	do
		unset ac_cv_search_libevent_rr_new
		saved_LDFLAGS="$LDFLAGS"
		saved_LIBS="$LIBS"
		LDFLAGS="$outer_LDFLAGS -L$d/lib $LDFLAGS"
		LIBS="$outer_LIBS"
		AC_SEARCH_LIBS([evutil_vsnprintf], [event], libevent_found="yes")
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$saved_LIBS"

		if test x"$libevent_found" = x"yes"
		then
			LIBEVENT_LIBDIRS="-L$d/lib"
			LIBEVENT_LIBS="-levent"
			break
		fi
	done
	if test x"$LIBEVENT_LIBS" = x""
	then
		AC_MSG_ERROR([libevent not found])
	fi
elif test x"$libeventpath" != x"no"
then
	libevent_found="no"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"
	LDFLAGS="$outer_LDFLAGS -L$d/lib $LDFLAGS"
	LIBS="$outer_LIBS"
	AC_SEARCH_LIBS([evutil_vsnprintf], [event], libevent_found="yes")
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"

	if test x"$libevent_found" = x"yes"
	then
		LIBEVENT_LIBDIRS="-L$d/lib"
		LIBEVENT_LIBS="-levent"
		break
	else
		AC_MSG_ERROR(libevent not found in $d)
	fi
fi

AC_SUBST(LIBEVENT_LIBDIRS)
AC_SUBST(LIBEVENT_LIBS)

#
# libtre
#
AC_ARG_WITH([tre],
            AS_HELP_STRING([--with-tre],
	                   [location of TRE includes and library]),
            [trepath="$withval"], [trepath="auto"])

tre_found="no"
LIBTRE_CPPFLAGS=""
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
                        LIBTRE_CPPFLAGS="-I$trepath/include"
                        LIBTRE_LIBS="-L$trepath/lib -ltre"
		elif test -f "$trepath/include/tre/regex.h"
		then
			tre_found="yes"
                        AC_MSG_RESULT([$trepath (old version)])
			AC_DEFINE([TRE_PRE_080], 1,
			          [version of libtre is older than 0.8.0])
                        LIBTRE_CPPFLAGS="-I$trepath/include"
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
				LIBTRE_CPPFLAGS="-I$trepath/include"
				LIBTRE_LIBS="-L$trepath/lib -ltre"
				break
			elif test -f $d/include/tre/regex.h
			then
				trepath=$d
				tre_found="yes"
				AC_MSG_RESULT([$d (old version)])
				AC_DEFINE([TRE_PRE_080], 1,
				          [version of libtre is older than 0.8.0])
				LIBTRE_CPPFLAGS="-I$trepath/include"
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
AC_SUBST([LIBTRE_CPPFLAGS])
AC_SUBST([LIBTRE_LIBS])

#
# liblua
#
AC_ARG_WITH([lua],
            AS_HELP_STRING([--with-lua],
                           [location of Lua includes and library]),
            [luapath="$withval"], [luapath="no"])

LIBLUA_INCDIRS=""
LIBLUA_LIBDIRS=""
LIBLUA_LIBS=""
lua_found="no"

if test \(  x"$luapath" = x"auto" -o x"$luapath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([LIBLUA], [lua5.1],
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
			AC_SEARCH_LIBS([dlopen], [dl])
			AC_DEFINE([USE_LUA], 1,
			          [support for Lua scripting])
			AC_SUBST([LUA_MANNOTICE], "")
			lua_found="yes"
			break
		elif test -f $d/include/lua52/lua.h
		then
			AC_MSG_RESULT($d)
			LIBLUA_INCDIRS="-I$d/include/lua52"
			LIBLUA_LIBDIRS="-L$d/lib/lua52"
			LIBLUA_LIBS="-llua -lm"
			AC_SEARCH_LIBS([dlopen], [dl])
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
			AC_SEARCH_LIBS([dlopen], [dl])
			AC_DEFINE([USE_LUA], 1,
			          [support for Lua scripting])
			AC_SUBST([LUA_MANNOTICE], "")
			lua_found="yes"
			break
		elif test -f $d/include/lua5.2/lua.h
		then
			AC_MSG_RESULT($d)
			LIBLUA_INCDIRS="-I$d/include/lua5.2"
			LIBLUA_LIBDIRS="-L$d/lib"
			LIBLUA_LIBS="-llua5.2 -lm"
			AC_SEARCH_LIBS([dlopen], [dl])
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
			AC_SEARCH_LIBS([dlopen], [dl])
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
		AC_SEARCH_LIBS([dlopen], [dl])
		lua_found="yes"
	elif test -f $luapath/include/lua52/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include/lua52"
		LIBLUA_LIBDIRS="-L$luapath/lib/lua52"
		LIBLUA_LIBS="-llua -lm"
		AC_SEARCH_LIBS([dlopen], [dl])
		lua_found="yes"
	elif test -f $luapath/include/lua5.1/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include/lua5.1"
		LIBLUA_LIBDIRS="-L$luapath/lib"
		LIBLUA_LIBS="-llua5.1 -lm"
		AC_SEARCH_LIBS([dlopen], [dl])
		lua_found="yes"
	elif test -f $luapath/include/lua5.2/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include/lua5.2"
		LIBLUA_LIBDIRS="-L$luapath/lib"
		LIBLUA_LIBS="-llua5.2 -lm"
		AC_SEARCH_LIBS([dlopen], [dl])
		lua_found="yes"
	elif test -f $luapath/include/lua.h
	then
		AC_MSG_RESULT($luapath)
		LIBLUA_INCDIRS="-I$luapath/include"
		LIBLUA_LIBDIRS="-L$luapath/lib"
		LIBLUA_LIBS="-llua -lm"
		AC_SEARCH_LIBS([dlopen], [dl])
		lua_found="yes"
	else
		AC_MSG_ERROR(not found at $luapath)
	fi
fi

if test x"$lua_found" = x"yes"
then
	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$outer_CPPFLAGS $LIBLUA_INCDIRS"
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

if test x"$enable_lua_only_signing" = x"yes" -a x"$lua_found" != x"yes"
then
	AC_MSG_ERROR([--enable-lua_only_signing requires Lua support])
fi

if test x"$enable_statsext" = x"yes" -a x"$lua_found" != x"yes"
then
	AC_MSG_ERROR([--enable-statsext requires Lua support])
fi

if test x"$enable_rbl" = x"yes" -a x"$lua_found" != x"yes"
then
	AC_MSG_ERROR([--enable-rbl requires Lua support])
fi

AC_ARG_WITH([sql-backend],
            AS_HELP_STRING([--with-sql-backend],
                           [selection of SQL backend in use]),
            [SQL_BACKEND="$withval"], [SQL_BACKEND="mysql"])
AC_SUBST(SQL_BACKEND)
AC_DEFINE_UNQUOTED(SQL_BACKEND, "$SQL_BACKEND", [default SQL back-end])

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
LIBODBX_LDFLAGS=""
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
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"
	if test x"$odbxpath" != x"auto" -a x"$odbxpath" != x"yes"
	then
		if test -f $odbxpath/include/odbx.h
		then
			LDFLAGS="$outer_LDFLAGS -L$odbxpath/lib"
			LIBS="$outer_LIBS"
			AC_SEARCH_LIBS(odbx_result_finish, opendbx,
			[
			        odbx_found="yes"
				LIBODBX_CPPFLAGS="-I$odbxpath/include"
				LIBODBX_LDFLAGS="-L$odbxpath/lib"
				LIBODBX_LIBS="$LIBS"
			],
			[
				AC_MSG_ERROR([opendbx not at least v1.3.7 at $odbxpath])
			],
			[-ldl])
		else
			AC_MSG_ERROR([opendbx not found at $odbxpath])
		fi
	else
		odbxdirs="/usr /usr/local"
		for d in $odbxdirs
		do
			if test -f $d/include/odbx.h
			then
				LDFLAGS="$outer_LDFLAGS -L$d/lib"
				LIBS="$outer_LIBS"
				AC_SEARCH_LIBS(odbx_result_finish, opendbx,
				[
					odbxpath=$d
			        	odbx_found="yes"
					LIBODBX_CPPFLAGS="-I$d/include"
					LIBODBX_LDFLAGS="-L$d/lib"
					LIBODBX_LIBS="$LIBS"
					break
				],[
					AC_MSG_ERROR([opendbx not at least v1.3.7 at $d])
				],
				[-ldl]
				)
			fi
		done
		if test x"$odbx_found" != x"yes"
		then
			AC_MSG_ERROR([opendbx not found])
		fi
	fi
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi
if test x"$odbx_found" = x"yes"
then
	AC_DEFINE([USE_ODBX], 1, [ODBX support for datasets enabled])
else
	if test x"$enable_stats" = x"yes"
	then
		AC_MSG_WARN([opendbx is needed to import statistics into a SQL database - disabling opendkim-importstats and opendkim-spam])
	fi
fi
AM_CONDITIONAL(USE_ODBX, test x"$odbx_found" = x"yes")
AC_SUBST(LIBODBX_CPPFLAGS)
AC_SUBST(LIBODBX_CFLAGS)
AC_SUBST(LIBODBX_LDFLAGS)
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
			OPENLDAP_LIBS="-L$ldappath/lib -lldap -llber"
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
				OPENLDAP_LIBS="-L$ldappath/lib -lldap -llber"
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
	CPPFLAGS="$outer_CPPFLAGS $OPENLDAP_CPPFLAGS"
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
				SASL_CPPFLAGS="-I$saslpath/include"
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
# libmdb
#
AC_ARG_WITH([lmdb],
            AS_HELP_STRING([--with-lmdb],
                           [location of OpenLDAP MDB includes and library]),
            [mdbpath="$withval"], [mdbpath="no"])

mdb_found="no"
LIBMDB_CPPFLAGS=""
LIBMDB_LIBS=""

if test x"$mdbpath" != x"no" -a x"$mdb_found" = x"no"
then
	saved_ldflags="$LDFLAGS"
	saved_cflags="$CFLAGS"
	CFLAGS="$outer_CFLAGS -pthread"
	if test x"$mdbpath" != x"auto" -a x"$mdbpath" != x"yes"
	then
		if test -f $mdbpath/include/lmdb.h
		then
			LDFLAGS="$outer_LDFLAGS -L$mdbpath/lib $STRL_LIBS"
			AC_CHECK_LIB(lmdb, mdb_env_open,
			[
			        mdb_found="yes"
				LIBMDB_CPPFLAGS="-I$mdbpath/include"
				LIBMDB_LIBS="-L$mdbpath/lib -llmdb"
			],
			[
				AC_MSG_ERROR([lmdb not valid at $mdbpath])
			]
			)
		else
			AC_MSG_ERROR([lmdb not found at $mdbpath])
		fi
	else
		mdbdirs="/usr /usr/local"
		for d in $mdbdirs
		do
			if test -f $d/include/lmdb.h
			then
				LDFLAGS="$outer_LDFLAGS -L$d/lib $STRL_LIBS"
				AC_CHECK_LIB(lmdb, mdb_env_open,
				[
					mdbpath=$d
			        	mdb_found="yes"
					LIBMDB_CPPFLAGS="-I$mdbpath/include"
					LIBMDB_LIBS="-L$mdbpath/lib -llmdb"
					break
				]
				)
			fi
		done
		if test x"$mdb_found" != x"yes"
		then
			AC_MSG_ERROR([lmdb not found])
		fi
	fi
	LDFLAGS="$saved_ldflags"
	CFLAGS="$saved_cflags"
fi
if test x"$mdb_found" = x"yes"
then
	AC_DEFINE([USE_MDB], 1, [OpenLDAP MDB support for datasets enabled])
fi
AM_CONDITIONAL(USE_MDB, test x"$mdb_found" = x"yes")
AC_SUBST(LIBMDB_CPPFLAGS)
AC_SUBST(LIBMDB_LIBS)

#
#
# libcurl, required by reputation
#
AC_ARG_WITH([libcurl],
            AS_HELP_STRING([--with-libcurl],
                           [location of CURL includes and library]),
            [curlpath="$withval"], [curlpath="auto"])

CURL_CPPFLAGS=""
CURL_LDFLAGS=""
CURL_LIBS=""

if test x"$enable_reputation" != x"yes" -a \
        x"$curlpath" = x"auto"
then
	curlpath="no"
fi

curl_found="no"
if test \( x"$curlpath" = x"auto" -o x"$curlpath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([CURL], [libcurl >= 7.12.0],
	[
		curl_found="yes"
		CURL_CPPFLAGS="$CURL_CFLAGS"
	],
	[
	        curl_found="no"
        	AC_MSG_WARN([pkg-config for curl not found, trying manual
		            search...])
        ])
fi

if test x"$curlpath" != x"no" -a x"$curl_found" = x"no"
then
	AC_MSG_CHECKING([for CURL])
	if test x"$curlpath" != x"auto" -a x"$curlpath" != x"yes"
	then
		if test -f $curlpath/include/curl/curl.h
		then
			AC_MSG_RESULT($curlpath)
		        curl_found="yes"
			CURL_CPPFLAGS="-I$curlpath/include"
			CURL_LDFLAGS="$outer_LDFLAGS -L$curlpath/lib"
			CURL_LIBS="-lcurl"
		else
			AC_MSG_ERROR(not found at $curlpath)
		fi
	else
		curldirs="/usr /usr/local"
		for d in $curldirs
		do
			if test -f $d/include/curl/curl.h
			then
				curlpath=$d
				AC_MSG_RESULT($d)
		        	curl_found="yes"
				CURL_CPPFLAGS="-I$curlpath/include"
				CURL_LDFLAGS="$outer_LDFLAGS -L$curlpath/lib"
				CURL_LIBS="-lcurl"
				break
			fi
		done
	fi
	if test x"$curl_found" != x"yes"
	then
		AC_MSG_RESULT([no])
	fi
fi

if test x"$curl_found" = x"yes"
then
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"
	CPPFLAGS="$CPPFLAGS $CURL_CPPFLAGS"
	LDFLAGS="$LDFLAGS $CURL_LDFLAGS"
	LIBS="$LIBS $CURL_LIBS"
	AC_CHECK_FUNC([curl_easy_strerror],
		      AC_DEFINE([HAVE_CURL_EASY_STRERROR], 1,
				[Define if libcurl has curl_easy_strerror()]))
	CPPFLAGS="$saved_CPPFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
	AC_SUBST([LIBCURL_MANNOTICE], "")
else
	AC_SUBST([LIBCURL_MANNOTICE],
	         "(Not enabled for this installation.)" )
fi

AC_SUBST(CURL_CPPFLAGS)
AC_SUBST(CURL_LDFLAGS)
AC_SUBST(CURL_LIBS)

if test x"$enable_reputation" = x"yes" -a \
        x"$curl_found" != x"yes"
then
	AC_MSG_ERROR([reputation requires curl])
fi

#
# reputation requires libjansson
# 

AC_ARG_WITH([libjansson],
            AS_HELP_STRING([--with-libjansson],
                           [location of jansson includes and library]),
            [janssonpath="$withval"], [janssonpath="auto"])

LIBJANSSON_CPPFLAGS=""
LIBJANSSON_LDFLAGS=""
LIBJANSSON_LIBS=""

# if reputation is disabled, we don't need it
if test x"$enable_reputation" != x"yes" -a \
        x"$janssonpath" = x"auto"
then
	janssonpath="no"
fi

jansson_found="no"
if test \( x"$janssonpath" = x"auto" -o x"$janssonpath" = x"yes" \) -a \
	x"$PKG_CONFIG" != x""
then
        PKG_CHECK_MODULES([LIBJANSSON], [jansson >= 2.2.1],
	[
		jansson_found="yes"
		LIBJANSSON_CPPFLAGS="$LIBJANSSON_CFLAGS"
		LIBJANSSON_LIBS="$LIBJANSSON_LIBS"
	],
	[
	        jansson_found="no"
        	AC_MSG_WARN([pkg-config for libjansson not found, trying manual
		            search...])
        ])
fi

if test x"$janssonpath" != x"no" -a x"$jansson_found" = x"no"
then
	AC_MSG_CHECKING([for libjansson])
	if test x"$janssonpath" != x"auto" -a x"$janssonpath" != x"yes"
	then
		if test -f $janssonpath/include/jansson.h
		then
			AC_MSG_RESULT($janssonpath)
		        jansson_found="yes"
			LIBJANSSON_CPPFLAGS="-I$janssonpath/include"
			LIBJANSSON_LDFLAGS="-L$janssonpath/lib"
			LIBJANSSON_LIBS="-ljansson"
		else
			AC_MSG_ERROR(not found at $janssonpath)
		fi
	else
		janssondirs="/usr /usr/local"
		for d in $janssondirs
		do
			if test -f $d/include/jansson.h
			then
				janssonpath=$d
				AC_MSG_RESULT($d)
		        	jansson_found="yes"
				LIBJANSSON_CPPFLAGS="-I$janssonpath/include"
				LIBJANSSON_LDFLAGS="-L$janssonpath/lib"
				LIBJANSSON_LIBS="-ljansson"
				break
			fi
		done
	fi
	if test x"$jansson_found" != x"yes"
	then
		AC_MSG_RESULT([no])
	fi
fi
AC_SUBST(LIBJANSSON_CPPFLAGS)
AC_SUBST(LIBJANSSON_LDFLAGS)
AC_SUBST(LIBJANSSON_LIBS)
AM_CONDITIONAL(JANSSON, test x"$LIBJANSSON_LIBS" != x"")

if test x"$enable_reputation" = x"yes" -a \
           x"$jansson_found" != x"yes"
then
	AC_MSG_ERROR([reputation requires libjansson])
fi

if test x"$jansson_found" == x"yes"
then
	AC_DEFINE(USE_JANSSON, 1, [use libjansson to parse REPUTE replies])
fi

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

rep_needs_bdb="no"
if test x"$enable_reputation" = x"yes" -a x"$mdb_found" = x"no"
then
	rep_needs_bdb="yes"
fi

AM_CONDITIONAL(USE_DB_OPENDKIM,
               test x"$enable_popauth" = x"yes" -o \
	            x"$rep_needs_bdb" = x"yes" -o \
	            x"$enable_ldap_caching" = x"yes" -o \
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

	# See if we can find a library by looking for db_create(), then
	# db_open(), then dbopen().
	#
	# This can cause compilation problems if for example a db.h
	# and a libdb are found that aren't the same version, but it's
	# worth a shot in general.
	if test x"$bdb_libdir" = x""
	then
		for d in $bdbdirs
		do
			saved_LDFLAGS="$LDFLAGS"
			saved_CPPFLAGS="$CPPFLAGS"
			saved_LIBS="$LIBS"
			LDFLAGS="$LDFLAGS -L$d/lib"
			CPPFLAGS="$CPPFLAGS -I$bdb_incdir"
			LIBS="$outer_LIBS"
			if test x"$libdbfound" = x"no"
			then
				AC_SEARCH_LIBS([db_create], $bdb_lib,
				               [libdbfound="yes"])
				bdb_libdir=$d/lib
			fi
			if test x"$libdbfound" = x"no"
			then
				AC_SEARCH_LIBS([db_open], $bdb_lib,
				               [libdbfound="yes"])
				bdb_libdir=$d/lib
			fi
			if test x"$libdbfound" = x"no"
			then
				AC_SEARCH_LIBS([dbopen], $bdb_lib,
				               [libdbfound="yes"])
				bdb_libdir=$d/lib
			fi

			LDFLAGS="$saved_LDFLAGS"
			CPPFLAGS="$saved_CPPFLAGS"
			LIBS="$saved_LIBS"
		done
	else
		saved_LDFLAGS="$LDFLAGS"
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LIBS="$LIBS"
		LDFLAGS="$LDFLAGS -L$bdb_libdir"
		CPPFLAGS="$CPPFLAGS -I$bdb_incdir"
		LIBS="$outer_LIBS"
		if test x"$libdbfound" = x"no"
		then
			AC_SEARCH_LIBS([db_create], $bdb_lib,
			               [libdbfound="yes"])
		fi
		if test x"$libdbfound" = x"no"
		then
			AC_SEARCH_LIBS([db_open], $bdb_lib,
			               [libdbfound="yes"])
		fi
		if test x"$libdbfound" = x"no"
		then
			AC_SEARCH_LIBS([dbopen], $bdb_lib,
			               [libdbfound="yes"])
		fi

		LDFLAGS="$saved_LDFLAGS"
		CPPFLAGS="$saved_CPPFLAGS"
		LIBS="$saved_LIBS"
	fi

	if test x"$libdbfound" = x"no"
	then
		AC_MSG_ERROR([cannot find db_create, db_open or dbopen])
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
	saved_CPPFLAGS="$CPPFLAGS"
	LDFLAGS="$LDFLAGS $LIBDB_LIBDIRS $LIBUNBOUND_LIBDIRS"
	CPPFLAGS="$CPPFLAGS $LIBDB_INCDIRS $LIBUNBOUND_INCDIRS"
	AC_CHECK_LIB([db], [log_file],
		AC_CHECK_LIB([unbound], [log_file],
			AC_MSG_ERROR([Cannot enable feature requiring BerkeleyDB with libunbound - both have log_file defined.  Please use newer BerkeleyDB version])
		)
	)
	LDFLAGS="$saved_LDFLAGS"
	CPPFLAGS="$saved_CPPFLAGS"
fi
AC_SUBST(LIBDB_INCDIRS)
AC_SUBST(LIBDB_LIBDIRS)
AC_SUBST(LIBDB_LIBS)

LIBOPENDKIM_LIBS="$LIBCRYPTO_LIBS $LIBTRE_LIBS $LIBRESOLV"
# This (below) is just for the pkg-config file opendkim.pc.in
LIBOPENDKIM_LIBS_PKG="$LIBOPENDKIM_LIBS"
LIBOPENDKIM_INC="$LIBCRYPTO_CPPFLAGS $LIBCRYPTO_CFLAGS $LIBTRE_CPPFLAGS"

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
# specify test socket
# 

AC_ARG_WITH([test-socket],
            AS_HELP_STRING([--with-test-socket],
                           [specify socket to use for all tests]),
            [testsocket="$withval"], [testsocket=""])
AM_CONDITIONAL(TEST_SOCKET, test x"$testsocket" != x"")
if test x"$testsocket" != x""
then
	TESTSOCKET=$testsocket
	AC_SUBST(TESTSOCKET)
fi

#
# Platform Specific Configuration
#
AC_CANONICAL_HOST
case "$host" in
	*-darwin*)
		CPPFLAGS="$CPPFLAGS -DBIND_8_COMPAT -DDARWIN"
		if test x"$unboundpath" = x"no"
		then
			AC_MSG_ERROR("unbound required on Darwin")
		fi
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

AC_ARG_WITH([erlang],
            AS_HELP_STRING([--with-erlang],
                           [location of Erlang includes and library]),
            [erlpath="$withval"], [erlpath="no"])

LIBERL_INCDIRS=""
LIBERL_LIBDIRS=""
LIBERL_LIBS=""
erl_found="no"

if test \( x"$erlpath" = x"yes" -o x"$erlpath" = x"auto" \)
then
	AC_MSG_CHECKING([for Erlang])
	b=`erl -noshell -eval 'io:format("~s~n", [[code:lib_dir()]]).' -s erlang halt`
	erlbase=`ls -d $b/erl_interface-* | tail -n1`
	AC_MSG_RESULT($erlbase)
	LIBERL_INCDIRS="-I$erlbase/include"
	LIBERL_LIBDIRS="-L$erlbase/lib"
	LIBERL_LIBS="-pthread -lerl_interface -lei"
	AC_DEFINE([USE_ERLANG], 1, [support for erlang access])
	erl_found="yes"
fi

if test x"$erlpath" != x"yes" -a x"$erlpath" != x"auto" -a x"$erlpath" != x"no"
then
	AC_MSG_CHECKING([for Erlang])
	if test -f $erlpath/include/ei.h
	then
		AC_MSG_RESULT($erlpath)
		LIBERL_INCDIRS="-I$erlpath/include"
		LIBERL_LIBDIRS="-L$erlpath/lib"
		LIBERL_LIBS="-pthread -lerl_interface -lei"
		erl_found="yes"
	else
		AC_MSG_ERROR(not found at $erlpath)
	fi
fi

if test x"$erl_found" = x"yes"
then
	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$outer_CPPFLAGS $LIBERL_INCDIRS"
	AC_DEFINE([USE_ERLANG], 1, [support for Erlang access])
	AC_SUBST([LIBERL_MANNOTICE], "")
else
	AC_SUBST([LIBERL_MANNOTICE], "(Not enabled for this installation.)")
fi

AM_CONDITIONAL(ERLANG, test x"$erl_found" = x"yes")
AC_SUBST(LIBERL_INCDIRS)
AC_SUBST(LIBERL_LIBDIRS)
AC_SUBST(LIBERL_LIBS)

#
# final command line tweaks
#

CPPFLAGS="$CPPFLAGS -DCONFIG_BASE=\\\"$sysconfdir\\\""

test "x$prefix" = xNONE && prefix=$ac_default_prefix 
SYSCONFDIR=`eval echo "$sysconfdir"`
AC_SUBST([SYSCONFDIR])

#
# for contrib/spec/opendkim.spec.in
#

installbin="no"
specconfig=""
specrequires=""
specbuildrequires=""

if test x"$enable_reputation" = x"yes"
then
	specconfig="$specconfig --enable-reputation"
	specrequires="$specrequires libcurl"
	specbuildrequires="$specbuildrequires libcurl-devel jansson-devel"
fi

if test x"$enable_stats" = x"yes"
then
	specconfig="$specconfig --enable-stats --with-odbx"
	specrequires="$specrequires libdb opendbx"
	specbuildrequires="$specbuildrequires libdb-devel opendbx-devel"
fi

if test x"$jansson_found" = x"yes"
then
	# autobuild
	installbin="yes"
	specconfig="$specconfig --with-libjansson=$janssonpath"
fi

# opendkim-spam
if test x"$enable_stats" = x"yes" -a x"$odbx_found" = x"yes"
then
	installbin="yes"
	specconfig="$specconfig --enable-stats --with-odbx=$odbxpath"
fi

# miltertest
if test x"$lua_found" = x"yes"
then
	installbin="yes"
	specconfig="$specconfig --with-lua=$luapath"
	specrequries="$specrequires lua"
	specbuildrequries="$specbuildrequires lua-devel"
fi

SPECBINDIR=""
if test x"$installbin" = x"yes"
then
	SPECBINDIR="%{_bindir}/*"
fi

SPECCONFIGURE="$specconfig"

if test x"$specrequires" = x""
then
	SPECREQUIRES=""
else
	SPECREQUIRES="Requires:$specrequires"
fi

if test x"$specbuildrequires" = x""
then
	SPECBUILDREQUIRES=""
else
	SPECBUILDREQUIRES="BuildRequires:$specbuildrequires"
fi

AC_SUBST(SPECBINDIR)
AC_SUBST(SPECCONFIGURE)
AC_SUBST(SPECREQUIRES)
AC_SUBST(SPECBUILDREQUIRES)

#
# Finish up
#
AC_OUTPUT([	Makefile
		docs/Makefile
		autobuild/Makefile
		contrib/Makefile
			contrib/convert/Makefile
			contrib/docs/Makefile
			contrib/init/Makefile
			contrib/init/generic/Makefile
			contrib/init/redhat/Makefile
			contrib/init/redhat/opendkim
			contrib/init/redhat/opendkim-default-keygen
			contrib/init/solaris/Makefile
			contrib/ldap/Makefile
			contrib/lua/Makefile
			contrib/patches/Makefile
			contrib/repute/Makefile
			contrib/spec/Makefile
			contrib/spec/opendkim.spec
			contrib/stats/Makefile
			contrib/systemd/Makefile
			contrib/systemd/opendkim.service
		libopendkim/opendkim.pc libopendkim/Makefile
		libopendkim/docs/Makefile
		libopendkim/tests/Makefile
		librbl/rbl.pc librbl/Makefile
		libut/ut.pc libut/Makefile
		libvbr/vbr.pc libvbr/Makefile
		miltertest/Makefile
		opendkim/Makefile opendkim/opendkim.8 opendkim/opendkim-genkey
			opendkim/opendkim-genkey.8 opendkim/opendkim-genzone.8
			opendkim/opendkim-lua.3 
			opendkim/opendkim-testkey.8 opendkim/opendkim-stats.8
			opendkim/opendkim-testmsg.8 opendkim/opendkim.conf.5
			opendkim/opendkim.conf.simple
			opendkim/opendkim.conf.simple-verify
			opendkim/opendkim-atpszone.8 opendkim/opendkim-spam.1
		opendkim/tests/Makefile
		stats/Makefile stats/opendkim-importstats.8
			stats/opendkim-expire
			stats/opendkim-expire.8
			stats/opendkim-gengraphs
			stats/opendkim-gengraphs.8
			stats/opendkim-genstats
			stats/opendkim-genstats.8
			stats/opendkim-reportstats
		reprrd/Makefile
			reprrd/opendkim-reprrdimport
			reprrd/opendkim-reprrdimport.8
			reprrd/reprrd.pc
		reputation/Makefile
			reputation/opendkim-genrates
			reputation/opendkim-genrates.8
			reputation/opendkim-modtotals
			reputation/opendkim-modtotals.8
			reputation/opendkim-rephistory
			reputation/opendkim-rephistory.8
			reputation/repute.pc
])
