/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _TEST_H_
#define _TEST_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libopendkim includes */
#include "dkim.h"

/* PROTOTYPES */
extern int dkimf_testfiles __P((DKIM_LIB *, char *, uint64_t, bool, int));

extern int dkimf_test_addheader __P((void *, char *, char *));
extern int dkimf_test_addrcpt __P((void *, char *));
extern int dkimf_test_chgheader __P((void *, char *, int, char *));
extern int dkimf_test_delrcpt __P((void *, char *));
extern void *dkimf_test_getpriv __P((void *));
extern char *dkimf_test_getsymval __P((void *, char *));
extern int dkimf_test_insheader __P((void *, int, char *, char *));
extern int dkimf_test_progress __P((void *));
extern int dkimf_test_quarantine __P((void *, char *));
extern int dkimf_test_setpriv __P((void *, void *));
extern int dkimf_test_setreply __P((void *, char *, char *, char *));

#endif /* _TEST_H_ */
