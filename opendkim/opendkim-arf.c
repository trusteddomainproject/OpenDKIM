/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.
**    All rights reserved.
**
*/

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

	  case ARF_TYPE_FRAUD:
		return "fraud";

	  case ARF_TYPE_VIRUS:
		return "virus";

	  case ARF_TYPE_AUTHFAIL:
		return "auth-failure";

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
