/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.4.28.1 2010/04/04 14:49:14 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.4.28.1 2010/04/04 14:49:14 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libdb includes */
#include <db.h>

/* libopendkim includes */
#include <dkim.h>

/* data types */
struct dkim_stats_key_v1
{
	dkim_canon_t	sk_hdrcanon;
	dkim_canon_t	sk_bodycanon;
	char		sk_sigdomain[DKIM_MAXHOSTNAMELEN + 1];
};

struct dkim_stats_data_v1
{
	bool		sd_lengths;
	time_t		sd_lastseen;
	dkim_alg_t	sd_lastalg;
	u_long		sd_pass;
	u_long		sd_fail;
};

struct dkim_stats_data_v2
{
	bool		sd_lengths;
	time_t		sd_lastseen;
	dkim_alg_t	sd_lastalg;
	dkim_canon_t	sd_lasthdrcanon;
	dkim_canon_t	sd_lastbodycanon;
	u_long		sd_total;
	u_long		sd_pass;
	u_long		sd_failhdr;
	u_long		sd_failbody;
	u_long		sd_extended;
	u_long		sd_chghdr_from;
	u_long		sd_chghdr_to;
	u_long		sd_chghdr_subject;
	u_long		sd_chghdr_other;
	u_long		sd_key_t;
	u_long		sd_key_g;
	u_long		sd_key_syntax;
	u_long		sd_key_missing;
	u_long		sd_sig_t;
	u_long		sd_sig_t_future;
	u_long		sd_sig_x;
	u_long		sd_sig_l;
	u_long		sd_sig_z;
	u_long		sd_adsp_found;
	u_long		sd_adsp_pass;
	u_long		sd_adsp_fail;
	u_long		sd_adsp_discardable;
	u_long		sd_authorsigs;
	u_long		sd_thirdpartysigs;
	u_long		sd_multiplesigs;
	u_long		sd_mailinglist;
};

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern void dkimf_stats_record __P((char *, const char *, dkim_canon_t,
                                    dkim_canon_t, dkim_alg_t, bool, bool,
                                    bool));

#endif /* _STATS_H_ */
