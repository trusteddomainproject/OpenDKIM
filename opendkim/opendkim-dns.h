/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2012, The OpenDKIM Project.  All rights reserved.
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

/* data types */
struct dkimf_unbound;

/* prototypes */
extern int dkimf_unbound_add_conffile __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_add_resolvconf __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_add_trustanchor __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_close __P((struct dkimf_unbound *));
extern int dkimf_unbound_init __P((struct dkimf_unbound **));
extern int dkimf_unbound_setup __P((DKIM_LIB *, struct dkimf_unbound *));
# ifdef _FFR_RBL
extern int dkimf_rbl_unbound_setup __P((RBL *, struct dkimf_unbound *));
# endif /* _FFR_RBL */
# ifdef _FFR_DKIM_REPUTATION
extern int dkimf_rep_unbound_setup __P((DKIM_REP, struct dkimf_unbound *));
# endif /* _FFR_DKIM_REPUTATION */
#endif /* USE_UNBOUND */

#ifdef USE_ARLIB
/* libar includes */
#include <async-resolv.h>

/* prototypes */
extern int dkimf_arlib_setup __P((DKIM_LIB *, AR_LIB));
# ifdef _FFR_RBL
extern int dkimf_rbl_arlib_setup __P((RBL *, AR_LIB));
# endif /* _FFR_RBL */
# ifdef _FFR_DKIM_REPUTATION
extern int dkimf_rep_arlib_setup __P((DKIM_REP, AR_LIB));
# endif /* _FFR_DKIM_REPUTATION */
#endif /* USE_ARLIB */

extern int dkimf_filedns_free __P((struct dkimf_filedns *));
extern int dkimf_filedns_setup __P((DKIM_LIB *, DKIMF_DB));

#endif /* _OPENDKIM_DNS_H_ */
