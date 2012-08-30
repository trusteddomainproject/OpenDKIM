/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _OPENDKIM_DNS_H_
#define _OPENDKIM_DNS_H_

/* system includes */
#include <sys/types.h>

/* libopendkim includes */
#include <dkim.h>

/* opendkim includes */
#include "opendkim-db.h"

#ifdef _FFR_RBL
/* librbl includes */
# include <rbl.h>
#endif /* _FFR_RBL */

#ifdef _FFR_DKIM_REPUTATION
/* libdkimrep includes */
# include <dkim-rep.h>
#endif /* _FFR_DKIM_REPUTATION */

struct dkimf_filedns;

#ifdef USE_UNBOUND
/* libunbound includes */
# include <unbound.h>

/* prototypes */
extern int dkimf_unbound_setup __P((DKIM_LIB *));
# ifdef _FFR_RBL
extern int dkimf_rbl_unbound_setup __P((RBL *));
# endif /* _FFR_RBL */
# ifdef _FFR_DKIM_REPUTATION
extern int dkimf_rep_unbound_setup __P((DKIM_REP));
# endif /* _FFR_DKIM_REPUTATION */
#endif /* USE_UNBOUND */

extern int dkimf_filedns_free __P((struct dkimf_filedns *));
extern int dkimf_filedns_setup __P((DKIM_LIB *, DKIMF_DB));

extern int dkimf_dns_config __P((DKIM_LIB *, const char *));
extern int dkimf_dns_setnameservers __P((DKIM_LIB *, const char *));
extern int dkimf_dns_trustanchor __P((DKIM_LIB *, const char *));

#endif /* _OPENDKIM_DNS_H_ */
