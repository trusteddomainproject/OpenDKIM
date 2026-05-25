/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _DKIM_CRYPTO_H_
#define _DKIM_CRYPTO_H_


/* PROTOTYPES */
#ifdef USE_GNUTLS
extern const char *dkimf_crypto_geterror (void);
#endif /* USE_GNUTLS */
extern int dkimf_crypto_init (void);
extern void dkimf_crypto_free (void);

#endif /* _DKIM_CRYPTO_H_ */
