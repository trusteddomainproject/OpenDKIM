/*
**  Copyright (c) 2006-2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: config.h,v 1.2 2009/07/20 21:28:19 cm-msk Exp $
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#ifndef lint
static char config_h_id[] = "@(#)$Id: config.h,v 1.2 2009/07/20 21:28:19 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <stdio.h>

/* opendkim includes */
#include "opendkim.h"

/* types and things */
#define	CONFIG_TYPE_STRING	0
#define	CONFIG_TYPE_INTEGER	1
#define	CONFIG_TYPE_BOOLEAN	2
#define	CONFIG_TYPE_INCLUDE	3

struct config
{
	bool		cfg_bool;
	u_int		cfg_type;
	int		cfg_int;
	char *		cfg_name;
	char *		cfg_string;
	struct config *	cfg_next;
};

struct configdef
{
	char *		cd_name;
	u_int		cd_type;
	u_int		cd_req;
};

/* prototypes */
extern char *config_check __P((struct config *, struct configdef *));
#ifdef DEBUG
extern void config_dump __P((struct config *, FILE *));
#endif /* DEBUG */
extern char *config_error __P((void));
extern void config_free __P((struct config *));
extern int config_get __P((struct config *, const char *, void *, size_t));
extern struct config *config_load __P((char *, struct configdef *,
                                       unsigned int *, char *, size_t));

#endif /* _CONFIG_H_ */
