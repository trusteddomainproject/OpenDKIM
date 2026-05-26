/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, 2014, The Trusted Domain Project.
**    All rights reserved.
**
*/

#ifndef _DKIM_ARF_H_
#define _DKIM_ARF_H_

/* system includes */
#include <sys/types.h>


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
#define	ARF_OPTIONS_DKIM_DNS	"d"
#define	ARF_OPTIONS_DKIM_OTHER	"o"
#define	ARF_OPTIONS_DKIM_POLICY	"p"
#define	ARF_OPTIONS_DKIM_SYNTAX	"s"
#define	ARF_OPTIONS_DKIM_VERIFY	"v"
#define	ARF_OPTIONS_DKIM_EXPIRED "x"

/* prototypes */
extern char *arf_dkim_failure_string (int);
extern char *arf_type_string (int);

#endif /* _DKIM_ARF_H_ */
