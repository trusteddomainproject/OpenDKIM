/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-arf.h,v 1.3 2009/08/03 19:10:47 cm-msk Exp $
*/

#ifndef _DKIM_ARF_H_
#define _DKIM_ARF_H_

#ifndef lint
static char dkim_arf_h_id[] = "@(#)$Id: opendkim-arf.h,v 1.3 2009/08/03 19:10:47 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

#define	ARF_VERSION		"0.1"

#define	ARF_TYPE_UNKNOWN	(-1)
#define	ARF_TYPE_ABUSE		0
#define	ARF_TYPE_FRAUD		1
#define	ARF_TYPE_VIRUS		2
#define	ARF_TYPE_AUTHFAIL	3
#define	ARF_TYPE_OTHER		4

#define ARF_DKIMF_UNKNOWN	(-1)
#define ARF_DKIMF_BODYHASH	0
#define ARF_DKIMF_REVOKED	1
#define ARF_DKIMF_SIGNATURE	2
#define ARF_DKIMF_SYNTAX	3
#define ARF_DKIMF_OTHER		4

#define	ARF_FORMAT_ARF		"arf"

#define	ARF_OPTIONS_DKIM_ALL	"all"
#define	ARF_OPTIONS_DKIM_SYNTAX	"s"
#define	ARF_OPTIONS_DKIM_VERIFY	"v"
#define	ARF_OPTIONS_DKIM_EXPIRED "x"

#define	ARF_OPTIONS_ADSP_ALL	"all"
#define	ARF_OPTIONS_ADSP_SIGNED	"s"
#define	ARF_OPTIONS_ADSP_UNSIGNED "u"

/* prototypes */
extern char *arf_dkim_failure_string __P((int));
extern char *arf_type_string __P((int));

#endif /* _DKIM_ARF_H_ */
