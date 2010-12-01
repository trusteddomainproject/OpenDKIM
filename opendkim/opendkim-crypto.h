/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-crypto.h,v 1.2 2009/08/03 19:14:12 cm-msk Exp $
*/

#ifndef _DKIM_CRYPTO_H_
#define _DKIM_CRYPTO_H_

#ifndef lint
static char opendkim_crypto_h_id[] = "@(#)$Id: opendkim-crypto.h,v 1.2 2009/08/03 19:14:12 cm-msk Exp $";
#endif /* !lint */

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* PROTOTYPES */
extern int dkimf_crypto_init __P((void));
extern void dkimf_crypto_free __P((void));

#endif /* _DKIM_CRYPTO_H_ */
