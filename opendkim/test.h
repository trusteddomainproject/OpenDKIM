/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: test.h,v 1.6 2009/11/17 20:09:23 cm-msk Exp $
*/

#ifndef _TEST_H_
#define _TEST_H_

#ifndef lint
static char test_h_id[] = "@(#)$Id: test.h,v 1.6 2009/11/17 20:09:23 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libopendkim includes */
#include "dkim.h"

/* PROTOTYPES */
extern int dkimf_testfile __P((DKIM_LIB *, char *, time_t, bool, int));

#ifdef _FFR_REDIRECT
extern int dkimf_test_addheader __P((void *, char *, char *));
extern int dkimf_test_addrcpt __P((void *, char *));
#endif /* _FFR_REDIRECT */
extern int dkimf_test_chgheader __P((void *, char *, int, char *));
#ifdef _FFR_REDIRECT
extern int dkimf_test_delrcpt __P((void *, char *));
#endif /* _FFR_REDIRECT */
extern void *dkimf_test_getpriv __P((void *));
extern char *dkimf_test_getsymval __P((void *, char *));
extern int dkimf_test_insheader __P((void *, int, char *, char *));
extern int dkimf_test_quarantine __P((void *, char *));
extern int dkimf_test_setpriv __P((void *, void *));
extern int dkimf_test_setreply __P((void *, char *, char *, char *));

#endif /* _TEST_H_ */
