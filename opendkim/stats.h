/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, The OpenDKIM Project.  All rights reserved.
**
**  $Id: stats.h,v 1.7 2010/07/23 19:12:20 cm-msk Exp $
*/

#ifndef _STATS_H_
#define _STATS_H_

#ifndef lint
static char stats_h_id[] = "@(#)$Id: stats.h,v 1.7 2010/07/23 19:12:20 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

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
	u_int		sd_received;
	struct sockaddr_storage sd_sockinfo;
	char		sd_fromdomain[DKIM_MAXHOSTNAMELEN + 1];
};

/* PROTOTYPES */
extern void dkimf_stats_init __P((void));
extern int dkimf_stats_record __P((char *, char *, DKIM *, dkim_policy_t,
                                   _Bool, u_int, struct sockaddr *));

#endif /* _STATS_H_ */
