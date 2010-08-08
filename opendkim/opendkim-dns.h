/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _OPENDKIM_DNS_H_
#define _OPENDKIM_DNS_H_

#ifndef lint
static char opendkim_dns_h_id[] = "@(#)$Id: opendkim-dns.h,v 1.1.2.1 2010/08/08 07:19:10 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

#ifdef USE_UNBOUND
/* system includes */
# include <pthread.h>

/* libopendkim includes */
# include <dkim.h>

/* libunbound includes */
# include <unbound.h>

/* data types */
struct dkimf_unbound;

/* prototypes */
extern int dkimf_unbound_add_trustanchor __P((struct dkimf_unbound *, char *));
extern int dkimf_unbound_close __P((struct dkimf_unbound *));
extern int dkimf_unbound_init __P((struct dkimf_unbound **));
extern int dkimf_unbound_setup __P((DKIM_LIB *, struct dkimf_unbound *));

#endif /* USE_UNBOUND */

#endif /* _OPENDKIM_DNS_H_ */
