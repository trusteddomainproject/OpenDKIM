#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
sinclude(acx_pthread.m4)

AC_INIT(OpenDKIM, 1.0.0, bugs@opendkim.org)
AM_INIT_AUTOMAKE(opendkim, 1.0.0)
AC_CONFIG_SRCDIR([libar/ar.c])
AC_CONFIG_HEADERS([build-config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Check for how to compile threaded stuff
ACX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

# Checks for libraries.
AC_SEARCH_LIBS(ERR_peek_error, crypto, , AC_MSG_ERROR(libcrypto not found))
AC_SEARCH_LIBS(SSL_library_init, ssl, , AC_MSG_ERROR(libssl not found))
AC_SEARCH_LIBS(smfi_getsymval, milter)
AC_SEARCH_LIBS(res_mkquery, resolv)

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strtol strtoul strtoull strlcpy strlcat])

# Libmilter
AC_MSG_CHECKING(for milter library and includes)
AC_ARG_WITH(milter,
	AS_HELP_STRING(--with-milter, location of milter includes and library (required)),
	milterpath="$withval", milterpath="auto")
milterdirs="/usr /usr/local"
if test "$milterpath" = "auto"
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
		AC_MSG_ERROR(milter is required)
		;;
	auto)
		AC_MSG_ERROR(milter not found)
		;;
	*/*)
		;;
	*)
		AC_MSG_ERROR(milter not found)
		;;
esac

LIBMILTER_INCLUDES="$milterpath/include"
LIBMILTER_LIBS="$milterpath/lib"
AC_SUBST(LIBMILTER_INCLUDES)
AC_SUBST(LIBMILTER_LIBS)
AC_MSG_RESULT($milterpath)

# Libunbound
AC_MSG_CHECKING(for libunbound)
AC_ARG_WITH(unbound,
	AS_HELP_STRING(--with-unbound, location of Unbound includes and library),
	unboundpath="$withval", unboundpath="no")

if test x"$unboundpath" = x"yes"
then
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
elif test x"$unboundpath" = x"no"
then
	AC_MSG_RESULT(no)
	LIBUNBOUND_INCDIRS=""
	LIBUNBOUND_LIBDIRS=""
	LIBUNBOUND_LIBS=""
else
	if test -f $unboundpath/include/unbound.h
	then
		AC_MSG_RESULT($unboundpath)
		LIBUNBOUND_INCDIRS="-I$unboundpath/include"
		LIBUNBOUND_LIBDIRS="-L$unboundpath/lib"
		LIBUNBOUND_LIBS="-lunbound"
	else
		AC_MSG_ERROR(not found at $unboundpath)
	fi
fi

AM_CONDITIONAL(USE_UNBOUND, test x"$unboundpath" != x"no")
AC_SUBST(LIBUNBOUND_INCDIRS)
AC_SUBST(LIBUNBOUND_LIBDIRS)
AC_SUBST(LIBUNBOUND_LIBS)

# libdb
AC_MSG_CHECKING(for BerkeleyDB)
AC_ARG_WITH(db,
	AS_HELP_STRING(--with-db, location of BerkeleyDB includes and library),
	bdb="$withval", bdb="no")

if test x"$bdb" = x"yes"
then
	bdbdirs="/usr /usr/local /usr/local/BerkeleyDB"
	for d in $bdbdirs
	do
		if test -f $d/include/db.h -a -f $d/lib/libdb.a
		then
			bdb=$d
			AC_MSG_RESULT($d)
			LIBDB_INCDIRS="-I$bdb/include"
			LIBDB_LIBDIRS="-L$bdb/lib"
			LIBDB_LIBS="-ldb"
			break;
		fi
	done
elif test x"$bdb" = x"no"
then
	AC_MSG_RESULT(no)
	LIBDB_INCDIRS=""
	LIBDB_LIBDIRS=""
	LIBDB_LIBS=""
else
	if test -f $d/include/db.h -a -f $d/lib/libdb.a
	then
		AC_MSG_RESULT($bdb)
		LIBDB_INCDIRS="-I$bdb/include"
		LIBDB_LIBDIRS="-L$bdb/lib"
		LIBDB_LIBS="-ldb"
	else
		AC_MSG_ERROR(not found at $bdb)
	fi
fi

AM_CONDITIONAL(USE_DB, test x"$bdb" != x"no")
AC_SUBST(LIBDB_INCDIRS)
AC_SUBST(LIBDB_LIBDIRS)
AC_SUBST(LIBDB_LIBS)

# Conditional stuff
AC_ARG_ENABLE(arlib, AS_HELP_STRING(--enable-arlib, enable provided asynchronous resolver library))
AM_CONDITIONAL(USE_ARLIB, test "$enable_arlib" = yes)

AC_ARG_ENABLE(bodylengthdb, AS_HELP_STRING(--enable-bodylengthdb, support for body length DBs))
AM_CONDITIONAL(BODYLENGTH_DB, test "$enable_bodylengthdb" = yes)

AC_ARG_ENABLE(captureerrors, AS_HELP_STRING(--enable-captureerrors, quarantine unknown verification failures))
AM_CONDITIONAL(CAPTURE_UNKNOWN_ERRORS, test "$enable_captureerrors" = yes)

AC_ARG_ENABLE(commaize, AS_HELP_STRING(--enable-commaize, clone sendmail header commaizing))
AM_CONDITIONAL(COMMAIZE, test "$enable_commaize" = yes)

AC_ARG_ENABLE(debug, AS_HELP_STRING(--enable-debug, produce debugging binaries and libraries))
AM_CONDITIONAL(DEBUG, test "$enable_debug" = yes)

AC_ARG_ENABLE(diffheaders, AS_HELP_STRING(--enable-diffheaders, compare signed and verified headers when possible))
AM_CONDITIONAL(DIFFHEADERS, test "$enable_diffheaders" = yes)

AC_ARG_ENABLE(dkimreputation, AS_HELP_STRING(--enable-dkimreputation, experimental DKIM reputation checks))
AM_CONDITIONAL(DKIM_REPUTATION, test "$enable_dkimreputation" = yes)

AC_ARG_ENABLE(dnsupgrade, AS_HELP_STRING(--enable-dnsupgrade, upgrade DNS to TCP when needed))
AM_CONDITIONAL(DNS_UPGRADE, test "$enable_dnsupgrade" = yes)

AC_ARG_ENABLE(multiplesigs, AS_HELP_STRING(--enable-multiplesigs, support for multiple signatures))
AM_CONDITIONAL(MULTIPLE_SIGNATURES, test "$enable_multiplesigs" = yes)

AC_ARG_ENABLE(parsetime, AS_HELP_STRING(--enable-parsetime, parse From: headers for sending times))
AM_CONDITIONAL(PARSE_TIME, test "$enable_parsetime" = yes)

AC_ARG_ENABLE(querycache, AS_HELP_STRING(--enable-querycache, local key/policy caching))
AM_CONDITIONAL(QUERY_CACHE, test "$enable_querycache" = yes)

AC_ARG_ENABLE(replacerules, AS_HELP_STRING(--enable-replacerules, support for string substitution when signing))
AM_CONDITIONAL(REPLACE_RULES, test "$enable_replacerules" = yes)

AC_ARG_ENABLE(reportintervals, AS_HELP_STRING(--enable-reportintervals, support for requested report intervals when reporting))
AM_CONDITIONAL(REPORT_INTERVALS, test "$enable_reportintervals" = yes)

AC_ARG_ENABLE(selectcanon, AS_HELP_STRING(--enable-selectcanon, allow sender to select canonicalization))
AM_CONDITIONAL(SELECT_CANONICALIZATION, test "$enable_selectcanon" = yes)

AC_ARG_ENABLE(senderheaders, AS_HELP_STRING(--enable-senderheaders, configurable sender header list))
AM_CONDITIONAL(SENDER_HEADERS, test "$enable_senderheaders" = yes)

AC_ARG_ENABLE(selectorheader, AS_HELP_STRING(--enable-selectorheader, special header to choose signing key))
AM_CONDITIONAL(SELECTOR_HEADER, test "$enable_selectorheader" = yes)

AC_ARG_ENABLE(stats, AS_HELP_STRING(--enable-stats, stats recording and reporting))
AM_CONDITIONAL(STATS, test "$enable_stats" = yes)

AC_ARG_ENABLE(vbr, AS_HELP_STRING(--enable-vbr, Vouch-By-Reference support))
AM_CONDITIONAL(VBR, test "$enable_vbr" = yes)

AC_ARG_ENABLE(ztags, AS_HELP_STRING(--enable-ztags, sign/verify with z= tags))
AM_CONDITIONAL(ZTAGS, test "$enable_ztags" = yes)

AC_OUTPUT(Makefile opendkim/Makefile libopendkim/Makefile libar/Makefile)
