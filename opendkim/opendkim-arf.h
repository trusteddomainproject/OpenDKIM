/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-arf.h,v 1.2 2009/07/20 21:28:19 cm-msk Exp $
*/

#ifndef _DKIM_ARF_H_
#define _DKIM_ARF_H_

#ifndef lint
static char dkim_arf_h_id[] = "@(#)$Id: opendkim-arf.h,v 1.2 2009/07/20 21:28:19 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>

#define	ARF_VERSION		"0.1"

#define	ARF_TYPE_UNKNOWN	(-1)
#define	ARF_TYPE_ABUSE		0
#define ARF_TYPE_DKIM		1
#define	ARF_TYPE_FRAUD		2
#define	ARF_TYPE_MISCATEGORIZED	3
#define	ARF_TYPE_NOTSPAM	4
#define	ARF_TYPE_OPTOUT		5
#define	ARF_TYPE_VIRUS		6
#define	ARF_TYPE_OTHER		7

#define ARF_DKIMF_UNKNOWN	(-1)
#define ARF_DKIMF_BODYHASH	0
#define ARF_DKIMF_GRANULARITY	1
#define ARF_DKIMF_REVOKED	2
#define ARF_DKIMF_SIGNATURE	3
#define ARF_DKIMF_SYNTAX	4
#define ARF_DKIMF_OTHER		5

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
