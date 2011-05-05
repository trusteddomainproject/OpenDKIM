/*
**  Copyright (c) 2010, 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _IPRANGE_H_
#define _IPRANGE_H_

#ifndef lint
static char iprange_h_id[] = "$Id$";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif /* HAVE_STDINT_H */

/* definitions */
#define	IPRANGE_DEFTIMEOUT		5
#define	IPRANGE_MAXHOSTNAMELEN	256
#define	IPRANGE_MAXERRORSTRING	256

/* return codes */
typedef int IPRANGE_STAT;

#define	IPRANGE_STAT_ERROR		(-1)
#define IPRANGE_STAT_OK			0
#define IPRANGE_STAT_INVALID		1
#define IPRANGE_STAT_DNSERROR		2
#define IPRANGE_STAT_NORESOURCE		3
#define IPRANGE_STAT_NOTIMPLEMENT	4
#define IPRANGE_STAT_NOTFOUND		5
#define	IPRANGE_STAT_FOUND		6	/* reply available */
#define	IPRANGE_STAT_NOREPLY		7	/* reply not available (yet) */
#define	IPRANGE_STAT_EXPIRED		8	/* no reply, query expired */

/* generic DNS error codes */
#define	IPRANGE_DNS_ERROR		(-1)	/* error in transit */
#define	IPRANGE_DNS_SUCCESS		0	/* reply available */
#define	IPRANGE_DNS_NOREPLY		1	/* reply not available (yet) */
#define	IPRANGE_DNS_EXPIRED		2	/* no reply, query expired */

/* types */
struct iprange_handle;
typedef struct iprange_handle IPRANGE;

/* prototypes */

/*
**  IPRANGE_INIT -- initialize an IPRANGE handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new IPRANGE handle suitable for use with other IPRANGE functions, or
**  	NULL on failure.
**  
**  Side effects:
**  	Strange radar returns at Indianapolis ARTCC.
*/

extern IPRANGE * iprange_init __P((void *(*caller_mallocf)(void *closure,
                                                           size_t nbytes),
                                   void (*caller_freef)(void *closure,
                                                        void *p),
                                   void *closure));

/*
**  IPRANGE_CLOSE -- shut down a IPRANGE instance
**
**  Parameters:
**  	iprange -- IPRANGE handle to shut down
**
**  Return value:
**  	None.
*/

extern void iprange_close __P((IPRANGE *));

/*
**  IPRANGE_GETERROR -- return any stored error string from within the IPRANGE
**                  context handle
**
**  Parameters:
**  	iprange -- IPRANGE handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const u_char *iprange_geterror __P((IPRANGE *));

/*
**  IPRANGE_SETDOMAIN -- declare the IPRANGE's domain (the query root)
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qroot-- certifiers string
**
**  Return value:
**  	None (yet).
*/

extern void iprange_setdomain __P((IPRANGE *, u_char *));

/*
**  IPRANGE_QUERY_START -- initiate a query to the IPRANGE for entries
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	query -- query string
**  	qh -- query handle (returned)
**
**  Return value:
**  	IPRANGE_STAT_INVALID -- iprange_setdomain() was not called,
**                              or "query" was NULL
** 	IPRANGE_STAT_* -- as defined
*/

extern IPRANGE_STAT iprange_query_start __P((IPRANGE *, u_char *, void **));

/*
**  IPRANGE_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- 32-bit buffer into which to write the result (can be NULL)
**
**  Return value:
** 	IPRANGE_STAT_* -- as defined
*/

extern IPRANGE_STAT iprange_query_check __P((IPRANGE *, void *,
                                             struct timeval *, uint32_t *));

/*
**  IPRANGE_QUERY_CANCEL -- cancel an open query to the IPRANGE
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	qh -- query handle
**
**  Return value:
** 	IPRANGE_STAT_* -- as defined
*/

extern IPRANGE_STAT iprange_query_cancel __P((IPRANGE *, void *));

/*
**  IPRANGE_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

extern void iprange_settimeout __P((IPRANGE *, u_int));

/*
**  IPRANGE_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

extern void iprange_setcallbackint __P((IPRANGE *, u_int));

/*
**  IPRANGE_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

extern void iprange_setcallbackctx __P((IPRANGE *, void *));

/*
**  IPRANGE_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	iprange -- IPRANGE handle, created by iprange_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

extern void iprange_setdnscallback __P((IPRANGE *rbl,
                                        void (*func)(const void *context)));

/*
**  IPRANGE_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	iprange -- IPRANGE library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

extern void *iprange_dns_set_query_service __P((IPRANGE *, void *));

/*
**  IPRANGE_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	lib -- IPRANGE library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             iprange_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

extern void iprange_dns_set_query_start __P((IPRANGE *,
                                             int (*)(void *, int,
                                                     unsigned char *,
                                                     unsigned char *,
                                                     size_t, void **)));

/*
**  IPRANGE_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	lib -- IPRANGE library handle
**  	func -- function to use to cancel running queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- query handle to be canceled
*/

extern void iprange_dns_set_query_cancel __P((IPRANGE *,
                                              int (*)(void *, void *)));

/*
**  IPRANGE_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	lib -- IPRANGE library handle
**  	func -- function to use to wait for a reply
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- DNS service handle
**  		void *qh -- handle of query that has completed
**  		struct timeval *timeout -- how long to wait
**  		size_t *bytes -- bytes returned
**  		int *error -- error code returned
**  		int *dnssec -- DNSSEC status returned
*/

extern void iprange_dns_set_query_waitreply __P((IPRANGE *,
                                                 int (*)(void *, void *,
                                                         struct timeval *,
                                                         size_t *, int *,
                                                         int *)));

#endif /* _IPRANGE_H_ */
