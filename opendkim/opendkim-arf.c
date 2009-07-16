/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-arf.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $
*/

#ifndef lint
static char opendkim_arf_c_id[] = "@(#)$Id: opendkim-arf.c,v 1.1 2009/07/16 20:59:11 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>

/* opendkim includes */
#include "opendkim-arf.h"

/*
**  ARF_TYPE_STRING -- translate an ARF_TYPE_* constant to a string
**
**  Parameters:
**  	type -- an ARF_TYPE_* constant
**
**  Return value:
**  	A string describing the "type" provided.
*/

char *
arf_type_string(int type)
{
	switch (type)
	{
	  case ARF_TYPE_ABUSE:
		return "abuse";

	  case ARF_TYPE_DKIM:
		return "dkim";

	  case ARF_TYPE_FRAUD:
		return "fraud";

	  case ARF_TYPE_MISCATEGORIZED:
		return "miscategorized";

	  case ARF_TYPE_NOTSPAM:
		return "not-spam";

	  case ARF_TYPE_OPTOUT:
		return "opt-out";

	  case ARF_TYPE_VIRUS:
		return "virus";

	  case ARF_TYPE_UNKNOWN:
	  case ARF_TYPE_OTHER:
	  default:
		return "other";
	}
}

/*
**  ARF_DKIM_FAILURE_STRING -- return an appropriate DKIM-Failure: string for
**                             an ARF report
**
**  Parameters:
**  	ftype -- failure type, i.e. an ARF_DKIMF_* constant
**
**  Return value:
**  	A string describing the "ftype" provided.
*/

char *
arf_dkim_failure_string(int ftype)
{
	switch (ftype)
	{
	  case ARF_DKIMF_BODYHASH:
		return "bodyhash";

	  case ARF_DKIMF_GRANULARITY:
		return "granularity";

	  case ARF_DKIMF_REVOKED:
		return "revoked";

	  case ARF_DKIMF_SIGNATURE:
		return "signature";

	  case ARF_DKIMF_SYNTAX:
		return "syntax";

	  case ARF_DKIMF_OTHER:
	  default:
		return "other";
	}
}
