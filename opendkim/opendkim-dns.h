/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _OPENDKIM_DNS_H_
#define _OPENDKIM_DNS_H_

#ifndef lint
static char opendkim_dns_h_id[] = "@(#)$Id: opendkim-dns.h,v 1.2 2010/08/30 22:01:56 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

/* libopendkim includes */
#include <dkim.h>

#ifdef _FFR_RBL
/* librbl includes */
# include <rbl.h>
#endif /* _FFR_RBL */

#ifdef USE_UNBOUND
/* libunbound includes */
# include <unbound.h>

/* data types */
struct dkimf_unbound;

/* prototypes */
extern int dkimf_unbound_add_conffile __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_add_trustanchor __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_close __P((struct dkimf_unbound *));
extern int dkimf_unbound_init __P((struct dkimf_unbound **));
extern int dkimf_unbound_setup __P((DKIM_LIB *, struct dkimf_unbound *));
# ifdef _FFR_RBL
extern int dkimf_rbl_unbound_setup __P((RBL *, struct dkimf_unbound *));
# endif /* _FFR_RBL */
#endif /* USE_UNBOUND */

#ifdef USE_ARLIB
/* libar includes */
#include <ar.h>

/* prototypes */
extern int dkimf_arlib_setup __P((DKIM_LIB *, AR_LIB));
# ifdef _FFR_RBL
extern int dkimf_rbl_arlib_setup __P((RBL *, AR_LIB));
# endif /* _FFR_RBL */
#endif /* USE_ARLIB */

#endif /* _OPENDKIM_DNS_H_ */
