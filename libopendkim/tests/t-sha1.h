/*
**  t-sha1.h -- skip helper for RSA-SHA1 signing tests
**
**  On platforms where the system crypto policy disables SHA1 for signing
**  (e.g. RHEL 9 / AlmaLinux 9 DEFAULT policy), tests that attempt RSA-SHA1
**  signing should skip rather than fail.  Include this header and call
**  SKIP_IF_NO_SHA1() at the top of main() in any test that uses
**  DKIM_SIGN_RSASHA1.
*/

#ifndef T_SHA1_H
#define T_SHA1_H

#ifndef HAVE_SHA1_SIGNING
# define SKIP_IF_NO_SHA1() \
	do { \
		printf("RSA-SHA1 signing not available on this platform, skipping\n"); \
		return 77; \
	} while (0)
#else
# define SKIP_IF_NO_SHA1() do { } while (0)
#endif

#endif /* T_SHA1_H */
