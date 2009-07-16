/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-crypto.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifndef _DKIM_CRYPTO_H_
#define _DKIM_CRYPTO_H_

#ifndef lint
static char dkim_crypto_h_id[] = "@(#)$Id: opendkim-crypto.h,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

/* PROTOTYPES */
extern int dkimf_crypto_init __P((void));
extern void dkimf_crypto_free __P((void));

#endif /* _DKIM_CRYPTO_H_ */
