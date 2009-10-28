/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.4 2009/10/28 03:30:27 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.4 2009/10/28 03:30:27 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libdb includes */
#include <db.h>

/* libopendkim includes */
#include <dkim.h>

/* data types */
struct dkim_stats_key
{
	dkim_canon_t	sk_hdrcanon;
	dkim_canon_t	sk_bodycanon;
	char		sk_sigdomain[DKIM_MAXHOSTNAMELEN + 1];
};

struct dkim_stats_data
{
	bool		sd_lengths;
	time_t		sd_lastseen;
	dkim_alg_t	sd_lastalg;
	u_long		sd_pass;
	u_long		sd_fail;
};

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern void dkimf_stats_record __P((char *, const char *, dkim_canon_t,
                                    dkim_canon_t, dkim_alg_t, bool, bool,
                                    bool));

#endif /* _STATS_H_ */
