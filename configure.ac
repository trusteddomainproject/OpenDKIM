#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT(OpenDKIM, 1.0.0, bugs@opendkim.org)
AM_INIT_AUTOMAKE(opendkim, 1.0.0)
AC_CONFIG_SRCDIR([libar/ar.c])
AC_CONFIG_HEADERS([build-config.h])

CFLAGS="$CFLAGS -pthread"

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.
AC_SEARCH_LIBS(ERR_peek_error, crypto)
AC_SEARCH_LIBS(SSL_library_init, ssl)
AC_SEARCH_LIBS(smfi_getsymval, milter)

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h libmilter/mfapi.h])

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

AC_OUTPUT(Makefile opendkim/Makefile libopendkim/Makefile libar/Makefile)
