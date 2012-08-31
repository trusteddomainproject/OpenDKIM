/*
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _RBL_H_
#define _RBL_H_

/* system includes */
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif /* HAVE_STDINT_H */

/* definitions */
#define	RBL_DEFTIMEOUT		5
#define	RBL_MAXHOSTNAMELEN	256
#define	RBL_MAXERRORSTRING	256

/* return codes */
typedef int RBL_STAT;

#define	RBL_STAT_ERROR		(-1)
#define RBL_STAT_OK		0
#define RBL_STAT_INVALID	1
#define RBL_STAT_DNSERROR	2
#define RBL_STAT_NORESOURCE	3
#define RBL_STAT_NOTIMPLEMENT	4
#define RBL_STAT_NOTFOUND	5
#define	RBL_STAT_FOUND		6		/* reply available */
#define	RBL_STAT_NOREPLY	7		/* reply not available (yet) */
#define	RBL_STAT_EXPIRED	8		/* no reply, query expired */

/* generic DNS error codes */
#define	RBL_DNS_ERROR		(-1)		/* error in transit */
#define	RBL_DNS_SUCCESS		0		/* reply available */
#define	RBL_DNS_NOREPLY		1		/* reply not available (yet) */
#define	RBL_DNS_EXPIRED		2		/* no reply, query expired */

/* types */
struct rbl_handle;
typedef struct rbl_handle RBL;

/* prototypes */

/*
**  RBL_INIT -- initialize an RBL handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new RBL handle suitable for use with other RBL functions, or
**  	NULL on failure.
**  
**  Side effects:
**  	Strange radar returns at Indianapolis ARTCC.
*/

extern RBL * rbl_init __P((void *(*caller_mallocf)(void *closure,
                                                   size_t nbytes),
                           void (*caller_freef)(void *closure, void *p),
                           void *closure));

/*
**  RBL_CLOSE -- shut down a RBL instance
**
**  Parameters:
**  	rbl -- RBL handle to shut down
**
**  Return value:
**  	None.
*/

extern void rbl_close __P((RBL *));

/*
**  RBL_GETERROR -- return any stored error string from within the RBL
**                  context handle
**
**  Parameters:
**  	rbl -- RBL handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const u_char *rbl_geterror __P((RBL *));

/*
**  RBL_SETDOMAIN -- declare the RBL's domain (the query root)
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qroot-- certifiers string
**
**  Return value:
**  	None (yet).
*/

extern void rbl_setdomain __P((RBL *, u_char *));

/*
**  RBL_QUERY_START -- initiate a query to the RBL for entries
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	query -- query string
**  	qh -- query handle (returned)
**
**  Return value:
**  	RBL_STAT_INVALID -- rbl_setdomain() was not called, or "query" was NULL
** 	RBL_STAT_* -- as defined
*/

extern RBL_STAT rbl_query_start __P((RBL *, u_char *, void **));

/*
**  RBL_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- 32-bit buffer into which to write the result (can be NULL)
**
**  Return value:
** 	RBL_STAT_* -- as defined
*/

extern RBL_STAT rbl_query_check __P((RBL *, void *, struct timeval *,
                                     uint32_t *));

/*
**  RBL_QUERY_CANCEL -- cancel an open query to the RBL
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	qh -- query handle
**
**  Return value:
** 	RBL_STAT_* -- as defined
*/

extern RBL_STAT rbl_query_cancel __P((RBL *, void *));

/*
**  RBL_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

extern void rbl_settimeout __P((RBL *, u_int));

/*
**  RBL_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

extern void rbl_setcallbackint __P((RBL *, u_int));

/*
**  RBL_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

extern void rbl_setcallbackctx __P((RBL *, void *));

/*
**  RBL_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	rbl -- RBL handle, created by rbl_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

extern void rbl_setdnscallback __P((RBL *rbl,
                                    void (*func)(const void *context)));

/*
**  RBL_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	rbl -- RBL library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

extern void *rbl_dns_set_query_service __P((RBL *, void *));

/*
**  RBL_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             rbl_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

extern void rbl_dns_set_query_start __P((RBL *,
                                         int (*)(void *, int,
                                                 unsigned char *,
                                                 unsigned char *,
                                                 size_t, void **)));

/*
**  RBL_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	lib -- RBL library handle
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

extern void rbl_dns_set_query_cancel __P((RBL *,
                                          int (*)(void *, void *)));

/*
**  RBL_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	lib -- RBL library handle
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

extern void rbl_dns_set_query_waitreply __P((RBL *,
                                             int (*)(void *, void *,
                                                     struct timeval *,
                                                     size_t *, int *,
                                                     int *)));

/*
**  RBL_DNS_SET_NSLIST -- set function that updates resolver nameserver list
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to update the nameserver list
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int
**  		void *srv -- DNS service handle
**  		const char *nslist -- nameserver list, as a comma-separated
**  			string
*/

extern void rbl_dns_set_nslist __P((RBL *,
                                    int (*)(void *, const char *)));

/*
**  RBL_DNS_SET_CLOSE -- shuts down the resolver
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to shut down the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns void
**  		void *srv -- DNS service handle
*/

extern void rbl_dns_set_close __P((RBL *,
                                   void (*)(void *)));

/*
**  RBL_DNS_SET_INIT -- initializes the resolver
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to initialize the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void **srv -- DNS service handle (updated)
*/

extern void rbl_dns_set_init __P((RBL *,
                                  int (*)(void **)));

/*
**  RBL_DNS_SET_CONFIG -- configures the resolver
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to configure the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *srv -- DNS service handle
**  		const char *config -- arbitrary resolver configuration data
*/

extern void rbl_dns_set_config __P((RBL *,
                                    int (*)(void *, const char *)));

/*
**  RBL_DNS_SET_TRUSTANCHOR -- provides trust anchor data to the resolver
**
**  Parameters:
**  	lib -- RBL library handle
**  	func -- function to use to pass trust anchor data to the resolver
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *srv -- DNS service handle
**  		const char *trust -- arbitrary trust anchor data
*/

extern void rbl_dns_set_trustanchor __P((RBL *,
                                         int (*)(void *, const char *)));

/*
**  RBL_DNS_NSLIST -- requests update to a nameserver list
**
**  Parameters:
**  	lib -- RBL library handle
**  	nslist -- comma-separated list of nameservers to use
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

extern RBL_STAT rbl_dns_nslist __P((RBL *, const char *));

/*
**  RBL_DNS_CONFIG -- requests a change to resolver configuration
**
**  Parameters:
**  	lib -- RBL library handle
**  	config -- opaque configuration string
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

extern RBL_STAT rbl_dns_config __P((RBL *, const char *));

/*
**  RBL_DNS_TRUSTANCHOR -- requests a change to resolver trust anchor data
**
**  Parameters:
**  	lib -- RBL library handle
**  	trust -- opaque trust anchor string
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

extern RBL_STAT rbl_dns_trustanchor __P((RBL *, const char *));

/*
**  RBL_DNS_INIT -- force nameserver (re)initialization
**
**  Parameters:
**  	lib -- RBL library handle
**
**  Return value:
**  	An RBL_STAT_* constant.
*/

extern RBL_STAT rbl_dns_init __P((RBL *));

#endif /* _RBL_H_ */
