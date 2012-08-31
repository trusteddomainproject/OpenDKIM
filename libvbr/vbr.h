/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _VBR_H_
#define _VBR_H_

/* system includes */
#include <sys/types.h>

/* strings */
#define	VBR_ALL			"all"
#define	VBR_INFOHEADER		"VBR-Info"
#define	VBR_PREFIX		"_vouch"

/* definitions */
#define	VBR_MAXHEADER		1024
#define	VBR_MAXHOSTNAMELEN	256

/* return codes */
typedef int VBR_STAT;

#define VBR_STAT_OK		0
#define VBR_STAT_INVALID	1
#define VBR_STAT_DNSERROR	2
#define VBR_STAT_NORESOURCE	3
#define VBR_STAT_NOTIMPLEMENT	4

#define	VBR_OPT_TRUSTEDONLY	0x01

/* types */
struct vbr_handle;
typedef struct vbr_handle VBR;

/* prototypes */

/*
**  VBR_INIT -- initialize a VBR handle
**
**  Parameters:
**  	caller_mallocf -- caller-provided memory allocation function
**  	caller_freef -- caller-provided memory release function
**  	closure -- memory closure to pass to the above when used
**
**  Return value:
**  	A new VBR handle suitable for use with other VBR functions, or
**  	NULL on failure.
**  
**  Side effects:
**  	Strange radar returns at Indianapolis ARTCC.
*/

extern VBR * vbr_init __P((void *(*caller_mallocf)(void *closure,
                                                   size_t nbytes),
                           void (*caller_freef)(void *closure, void *p),
                           void *closure));

/*
**  VBR_OPTIONS -- set VBR options
**
**  Parameters:
**  	vbr -- VBR handle to modify
**  	opts -- bitmask of options to use
**
**  Return value:
**  	None.
*/

extern void vbr_options __P((VBR *, unsigned int));

/*
**  VBR_CLOSE -- shut down a VBR instance
**
**  Parameters:
**  	vbr -- VBR handle to shut down
**
**  Return value:
**  	None.
*/

extern void vbr_close __P((VBR *));

/*
**  VBR_GETERROR -- return any stored error string from within the VBR
**                  context handle
**
**  Parameters:
**  	vbr -- VBR handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const u_char *vbr_geterror __P((VBR *));

/*
**  VBR_GETHEADER -- generate and store the VBR-Info header
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	hdr -- header buffer
**  	len -- number of bytes available at "hdr"
**
**  Return value:
**  	STAT_OK -- success
**  	STAT_NORESOURCE -- "hdr" was too short
*/

extern VBR_STAT vbr_getheader __P((VBR *, unsigned char *, size_t));

/*
**  VBR_SETCERT -- store the VBR certifiers of this message
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cert -- certifiers string
**
**  Return value:
**  	None (yet).
*/

extern void vbr_setcert __P((VBR *, u_char *));

/*
**  VBR_SETTYPE -- store the VBR type of this message
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	type -- type string
**
**  Return value:
**  	None (yet).
*/

extern void vbr_settype __P((VBR *, u_char *));

/*
**  VBR_SETDOMAIN -- declare the sender's domain
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cert -- certifiers string
**
**  Return value:
**  	None (yet).
*/

extern void vbr_setdomain __P((VBR *, u_char *));

/*
**  VBR_TRUSTEDCERTS -- set list of trusted certifiers
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	certs -- NULL terminted vector of trusted certifier names
**
**  Return value:
**  	None (yet).
*/

extern void vbr_trustedcerts __P((VBR *, u_char **));

/*
**  VBR_QUERY -- query the vouching servers for results
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	res -- result string (one of "fail", "pass"); returned
**  	cert -- name of the certifier that returned a "pass"; returned
**
**  Return value:
**  	VBR_STAT_OK -- able to determine a result
**  	VBR_STAT_INVALID -- vbr_trustedcerts(), vbr_settype() and
**  	                     vbr_setcert() were not all called
**  	VBR_STAT_CANTVRFY -- DNS issue prevented resolution
**
**  Notes:
**  	- "pass" is the result if ANY certifier vouched for the message.
**  	- "res" is not modified if no result could be determined
**  	- "cert" and "domain" are not modified if a "pass" is not returned
**  	- there's no attempt to validate the values found
*/

extern VBR_STAT vbr_query __P((VBR *, u_char **, u_char **));

/*
**  VBR_SETTIMEOUT -- set the DNS timeout
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	timeout -- requested timeout (seconds)
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

extern VBR_STAT vbr_settimeout __P((VBR *, u_int));

/*
**  VBR_SETCALLBACKINT -- set the DNS callback interval
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	cbint -- requested callback interval (seconds)
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

extern VBR_STAT vbr_setcallbackint __P((VBR *, u_int));

/*
**  VBR_SETCALLBACKCTX -- set the DNS callback context
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	ctx -- context to pass to the DNS callback
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

extern VBR_STAT vbr_setcallbackctx __P((VBR *, void *));

/*
**  VBR_SETDNSCALLBACK -- set the DNS wait callback
**
**  Parameters:
**  	vbr -- VBR handle, created by vbr_init()
**  	func -- function to call; should take an opaque context pointer
**
**  Return value:
**  	A VBR_STAT_* constant.
*/

extern VBR_STAT vbr_setdnscallback __P((VBR *vbr,
                                        void (*func)(const void *context)));

/*
**  VBR_DNS_SET_QUERY_SERVICE -- stores a handle representing the DNS
**                               query service to be used, returning any
**                               previous handle
**
**  Parameters:
**  	vbr -- VBR library handle
**  	h -- handle to be used
**
**  Return value:
**  	Previously stored handle, or NULL if none.
*/

extern void *vbr_dns_set_query_service __P((VBR *, void *));

/*
**  VBR_DNS_SET_QUERY_START -- stores a pointer to a query start function
**
**  Parameters:
**  	vbr -- VBR library handle
**  	func -- function to use to start queries
**
**  Return value:
**  	None.
**
**  Notes:
**  	"func" should match the following prototype:
**  		returns int (status)
**  		void *dns -- receives handle stored by
**  		             vbr_dns_set_query_service()
**  		int type -- DNS RR query type (C_IN assumed)
**  		char *query -- question to ask
**  		char *buf -- buffer into which to write reply
**  		size_t buflen -- size of buf
**  		void **qh -- returned query handle
*/

extern void vbr_dns_set_query_start __P((VBR *, int (*)(void *, int,
                                                        unsigned char *,
                                                        unsigned char *,
                                                        size_t, void **)));

/*
**  VBR_DNS_SET_QUERY_CANCEL -- stores a pointer to a query cancel function
**
**  Parameters:
**  	vbr -- VBR library handle
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

extern void vbr_dns_set_query_cancel __P((VBR *, int (*)(void *, void *)));

/*
**  VBR_DNS_SET_QUERY_WAITREPLY -- stores a pointer to wait for a DNS reply
**
**  Parameters:
**  	vbr -- VBR library handle
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

extern void vbr_dns_set_query_waitreply __P((VBR *, int (*)(void *, void *,
                                                            struct timeval *,
                                                            size_t *, int *,
                                                            int *)));

/*
**  VBR_DNS_SET_NSLIST -- set function that updates resolver nameserver list
**
**  Parameters:
**  	lib -- VBR library handle
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

extern void vbr_dns_set_nslist __P((VBR *,
                                    int (*)(void *, const char *)));

/*
**  VBR_DNS_SET_CLOSE -- shuts down the resolver
**
**  Parameters:
**  	lib -- VBR library handle
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

extern void vbr_dns_set_close __P((VBR *,
                                   void (*)(void *)));

/*
**  VBR_DNS_SET_INIT -- initializes the resolver
**
**  Parameters:
**  	lib -- VBR library handle
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

extern void vbr_dns_set_init __P((VBR *,
                                  int (*)(void **)));

/*
**  VBR_DNS_SET_CONFIG -- configures the resolver
**
**  Parameters:
**  	lib -- VBR library handle
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

extern void vbr_dns_set_config __P((VBR *,
                                    int (*)(void *, const char *)));

/*
**  VBR_DNS_SET_TRUSTANCHOR -- provides trust anchor data to the resolver
**
**  Parameters:
**  	lib -- VBR library handle
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

extern void vbr_dns_set_trustanchor __P((VBR *,
                                         int (*)(void *, const char *)));

/*
**  VBR_DNS_NSLIST -- requests update to a nameserver list
**
**  Parameters:
**  	lib -- VBR library handle
**  	nslist -- comma-separated list of nameservers to use
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

extern VBR_STAT vbr_dns_nslist __P((VBR *, const char *));

/*
**  VBR_DNS_CONFIG -- requests a change to resolver configuration
**
**  Parameters:
**  	lib -- VBR library handle
**  	config -- opaque configuration string
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

extern VBR_STAT vbr_dns_config __P((VBR *, const char *));

/*
**  VBR_DNS_TRUSTANCHOR -- requests a change to resolver trust anchor data
**
**  Parameters:
**  	lib -- VBR library handle
**  	trust -- opaque trust anchor string
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

extern VBR_STAT vbr_dns_trustanchor __P((VBR *, const char *));

/*
**  VBR_DNS_INIT -- force nameserver (re)initialization
**
**  Parameters:
**  	lib -- VBR library handle
**
**  Return value:
**  	An VBR_STAT_* constant.
*/

extern VBR_STAT vbr_dns_init __P((VBR *));

#endif /* _VBR_H_ */
