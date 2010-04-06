/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.4.28.7 2010/04/06 20:33:55 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.4.28.7 2010/04/06 20:33:55 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libdb includes */
#include <db.h>

/* libopendkim includes */
#include <dkim.h>

/* current version */
#define DKIMF_STATS_VERSION	2

/* sentinel record */
#define	DKIMF_STATS_SENTINEL	"@"

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
	time_t		sd_when;
	dkim_alg_t	sd_alg;
	dkim_canon_t	sd_hdrcanon;
	dkim_canon_t	sd_bodycanon;
	u_int		sd_totalsigs;
	u_int		sd_pass;
	u_int		sd_fail;
	u_int		sd_failbody;
	u_int		sd_extended;
	u_int		sd_chghdr_from;
	u_int		sd_chghdr_to;
	u_int		sd_chghdr_subject;
	u_int		sd_chghdr_other;
	u_int		sd_key_t;
	u_int		sd_key_g;
	u_int		sd_key_syntax;
	u_int		sd_key_missing;
	u_int		sd_sig_t;
	u_int		sd_sig_t_future;
	u_int		sd_sig_x;
	u_int		sd_sig_l;
	u_int		sd_sig_z;
	u_int		sd_adsp_found;
	u_int		sd_adsp_fail;
	u_int		sd_adsp_discardable;
	u_int		sd_authorsigs;
	u_int		sd_authorsigsfail;
	u_int		sd_thirdpartysigs;
	u_int		sd_thirdpartysigsfail;
	u_int		sd_mailinglist;
};

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern void dkimf_stats_record __P((char *, char *, DKIM *, dkim_policy_t,
                                    _Bool));

#endif /* _STATS_H_ */
