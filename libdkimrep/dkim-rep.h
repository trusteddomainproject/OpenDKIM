/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_REP_H_
#define _DKIM_REP_H_

#ifndef lint
static char dkim_rep_h_id[] = "@(#)$Id: dkim-rep.h,v 1.2 2009/07/23 17:40:23 cm-msk Exp $";
#endif /* !lint */

/* data types */
typedef int DKIM_REP_STAT;

struct dkim_rep_handle;
typedef struct dkim_rep_handle * DKIM_REP;

/* macros */
#define	DKIM_REP_STAT_OK	0
#define	DKIM_REP_STAT_SYNTAX	1
#define	DKIM_REP_STAT_NOTFOUND	2
#define	DKIM_REP_STAT_FOUND	3
#define	DKIM_REP_STAT_ERROR	4
#define	DKIM_REP_STAT_EXPIRED	5
#define	DKIM_REP_STAT_NOREPLY	6

#define	DKIM_REP_DNS_SUCCESS	0
#define	DKIM_REP_DNS_ERROR	1
#define	DKIM_REP_DNS_EXPIRED	2
#define	DKIM_REP_DNS_NOREPLY	3

#define	DKIM_REP_DEFROOT	"al.dkim-reputation.org"

/* prototypes */

/*
**  DKIM_REP_INIT -- initialize an DKIM_REP handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new DKIM_REP handle suitable for use with other DKIM_REP
**  	functions, or NULL on failure.
**  
**  Side effects:
**  	Small but detectable movement of the Indian subcontinent.
*/

extern DKIM_REP dkim_rep_init __P((void *(*caller_mallocf)(void *closure,
                                                           size_t nbytes),
                                   void (*caller_freef)(void *closure,
                                                        void *p),
                                   void *closure));

/*
**  DKIM_REP_CLOSE -- shut down a DKIM_REP instance
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle to shut down
**
**  Return value:
**  	None.
*/

extern void dkim_rep_close __P((DKIM_REP));

/*
**  DKIM_REP_GETERROR -- return any stored error string from within the
**                       DKIM_REP context handle
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const u_char *dkim_rep_geterror __P((DKIM_REP));

/*
**  DKIM_REP_SETDOMAIN -- declare the DKIM_REP's domain (the query root)
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qroot-- certifiers string
**
**  Return value:
**  	None (yet).
*/

extern void dkim_rep_setdomain __P((DKIM_REP, u_char *));

/*
**  DKIM_REP_QUERY_START -- initiate a query to the DKIM_REP for entries
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	user -- local-part of From:
**  	domain -- domain part of From:
**  	signdomain -- signing domain
**  	qh -- query handle (returned)
**
**  Return value:
**  	DKIM_REP_STAT_INVALID -- dkim_rep_setdomain() was not called,
**                               or "query" was NULL
** 	DKIM_REP_STAT_* -- as defined
*/

extern DKIM_REP_STAT dkim_rep_query_start __P((DKIM_REP, u_char *, u_char *,
                                               u_char *, void **));

/*
**  DKIM_REP_QUERY_CHECK -- check for a reply from an active query
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qh -- query handle (returned)
**  	timeout -- timeout
**  	res -- integer into which to write the result (can be NULL)
**
**  Return value:
** 	DKIM_REP_STAT_* -- as defined
*/

extern DKIM_REP_STAT dkim_rep_query_check __P((DKIM_REP, void *,
                                               struct timeval *, int *));

/*
**  DKIM_REP_QUERY_CANCEL -- cancel an open query to the service
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	qh -- query handle
**
**  Return value:
** 	DKIM_REP_STAT_* -- as defined
*/

extern DKIM_REP_STAT dkim_rep_query_cancel __P((DKIM_REP, void *));

/*
**  DKIM_REP_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	None.
*/

extern void dkim_rep_settimeout __P((DKIM_REP, u_int));

/*
**  DKIM_REP_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	None.
*/

extern void dkim_rep_setcallbackint __P((DKIM_REP, u_int));

/*
**  DKIM_REP_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	None.
*/

extern void dkim_rep_setcallbackctx __P((DKIM_REP, void *));

/*
**  DKIM_REP_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	dkim_rep -- DKIM_REP handle, created by dkim_rep_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	None.
*/

extern void dkim_rep_setdnscallback __P((DKIM_REP, void (*)(const void *)));

/*
**  DKIM_REP_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                                    query service to be used, returning any
**                                    previous handle
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

extern void *dkim_rep_dns_set_query_service __P((DKIM_REP, void *));

/*
**  DKIM_REP_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             dkim_rep_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

extern void dkim_rep_dns_set_query_start __P((DKIM_REP,
                                              int (*)(void *, int,
                                                      unsigned char *,
                                                      unsigned char *,
                                                      size_t, void **)));

/*
**  DKIM_REP_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel
**                                   function
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
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

extern void dkim_rep_dns_set_query_cancel __P((DKIM_REP,
                                               int (*)(void *, void *)));

/*
**  DKIM_REP_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a
**                                      DNS reply
**
**  Parameters:
**  	dkim_rep -- DKIM_REP library handle
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

extern void dkim_rep_dns_set_query_waitreply __P((DKIM_REP,
                                                  int (*)(void *, void *,
                                                          struct timeval *,
                                                          size_t *, int *,
                                                          int *)));

#endif /* ! _DKIM_REP_H_ */
