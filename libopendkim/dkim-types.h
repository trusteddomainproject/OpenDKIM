/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _DKIM_TYPES_H_
#define _DKIM_TYPES_H_

#ifndef lint
static char dkim_types_h_id[] = "@(#)$Id: dkim-types.h,v 1.3 2009/07/21 23:36:39 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <regex.h>

/* libar includes */
#if USE_ARLIB
# include <ar.h>
#endif /* USE_ARLIB */

/* OpenSSL includes */
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#ifdef QUERY_CACHE
/* libdb includes */
# include <db.h>
#endif /* QUERY_CACHE */

#ifdef USE_UNBOUND
/* libunbound includes */
# include <unbound.h>
#endif /* USE_UNBOUND */

/* libdkim includes */
#include "dkim.h"

/* struct dkim_pstate -- policy query state */
struct dkim_pstate
{
	unsigned int		ps_pflags;
	int			ps_qstatus;
	int			ps_state;
	dkim_policy_t		ps_policy;
};

/* struct dkim_dstring -- a dynamically-sized string */
struct dkim_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	DKIM *			ds_dkim;
	char *			ds_buf;
};

/* struct dkim_header -- an RFC2822 header of some kind */
struct dkim_header
{
	int			hdr_flags;
	size_t			hdr_textlen;
	size_t			hdr_namelen;
	u_char *		hdr_text;
	u_char *		hdr_colon;
	struct dkim_header *	hdr_next;
};

/* hdr_flags bits */
#define	DKIM_HDR_SIGNED		0x01

/* struct dkim_plist -- a parameter/value pair */
struct dkim_plist
{
	u_char *		plist_param;
	u_char *		plist_value;
	struct dkim_plist *	plist_next;
};

/* struct dkim_set -- a set of parameter/value pairs */
struct dkim_set
{
	_Bool			set_bad;
	dkim_set_t		set_type;
	u_char *		set_data;
	void *			set_udata;
	struct dkim_plist *	set_plist;
	struct dkim_set *	set_next;
};

/* struct dkim_siginfo -- signature information for use by the caller */
struct dkim_siginfo
{
	u_int			sig_flags;
	u_int			sig_error;
	u_int			sig_bh;
	u_int			sig_version;
	u_int			sig_hashtype;
	u_int			sig_keytype;
	u_int			sig_keybits;
#ifdef USE_UNBOUND
	u_int			sig_dnssec_key;
#endif /* USE_UNBOUND */
	size_t			sig_siglen;
	size_t			sig_keylen;
	size_t			sig_b64keylen;
	dkim_query_t		sig_query;
	dkim_alg_t		sig_signalg;
	dkim_canon_t		sig_hdrcanonalg;
	dkim_canon_t		sig_bodycanonalg;
	unsigned long long	sig_timestamp;
	u_char *		sig_domain;
	u_char *		sig_selector;
	u_char *		sig_sig;
	u_char *		sig_key;
	u_char *		sig_b64key;
	void *			sig_context;
	void *			sig_signature;
	struct dkim_canon *	sig_hdrcanon;
	struct dkim_canon *	sig_bodycanon;
	struct dkim_set *	sig_taglist;
	struct dkim_set *	sig_keytaglist;
};

/* struct dkim_sha1 -- stuff needed to do a sha1 hash */
struct dkim_sha1
{
	int			sha1_tmpfd;
	BIO *			sha1_tmpbio;
	SHA_CTX			sha1_ctx;
	u_char			sha1_out[SHA_DIGEST_LENGTH];
};

#ifdef SHA256_DIGEST_LENGTH
/* struct dkim_sha256 -- stuff needed to do a sha256 hash */
struct dkim_sha256
{
	int			sha256_tmpfd;
	BIO *			sha256_tmpbio;
	SHA256_CTX		sha256_ctx;
	u_char			sha256_out[SHA256_DIGEST_LENGTH];
};
#endif /* SHA256_DIGEST_LENGTH */

/* struct dkim_canon -- a canonicalization status handle */
struct dkim_canon
{
	_Bool			canon_done;
	_Bool			canon_hdr;
	_Bool			canon_blankline;
	int			canon_lastchar;
	u_int			canon_hashtype;
	u_int			canon_blanks;
	size_t			canon_hashbuflen;
	size_t			canon_hashbufsize;
	off_t			canon_remain;
	off_t			canon_wrote;
	off_t			canon_length;
	dkim_canon_t		canon_canon;
	u_char *		canon_hashbuf;
	u_char *		canon_hdrlist;
	void *			canon_hash;
	struct dkim_header *	canon_sigheader;
	struct dkim_canon *	canon_next;
};

/* struct dkim_rsa -- stuff needed to do RSA sign/verify */
struct dkim_rsa
{
	u_char			rsa_pad;
	size_t			rsa_keysize;
	size_t			rsa_rsainlen;
	size_t			rsa_rsaoutlen;
	EVP_PKEY *		rsa_pkey;
	RSA *			rsa_rsa;
	u_char *		rsa_rsain;
	u_char *		rsa_rsaout;
};

/* struct dkim_test_dns_data -- simulated DNS replies */
struct dkim_test_dns_data
{
	int			dns_class;
	int			dns_type;
	int			dns_prec;
	u_char *		dns_query;
	u_char *		dns_reply;
	struct dkim_test_dns_data * dns_next;
};

/* struct dkim_unbound_cb_data -- libunbound callback data */
struct dkim_unbound_cb_data
{
	int			ubd_done;
	int			ubd_rcode;
	int			ubd_id;
	int			ubd_type;
	u_int			ubd_result;
	DKIM_STAT		ubd_stat;
	size_t			ubd_buflen;
	u_char *		ubd_buf;
	const char *		ubd_jobid;
};

/* struct dkim -- a complete DKIM transaction context */
struct dkim
{
	_Bool			dkim_partial;
	_Bool			dkim_bodydone;
	_Bool			dkim_subdomain;
	_Bool			dkim_skipbody;
	int			dkim_mode;
	int			dkim_state;
	int			dkim_chunkstate;
	int			dkim_chunksm;
	int			dkim_timeout;
	int			dkim_presult;
	int			dkim_hdrcnt;
#ifdef QUERY_CACHE
	u_int			dkim_cache_queries;
	u_int			dkim_cache_hits;
#endif /* QUERY_CACHE */
	u_int			dkim_version;
	u_int			dkim_sigcount;
#ifdef USE_UNBOUND
	u_int			dkim_dnssec_policy;
#endif /* USE_UNBOUND */
	size_t			dkim_margin;
	size_t			dkim_b64siglen;
	size_t			dkim_keylen;
	size_t			dkim_errlen;
	time_t			dkim_timestamp;
#ifdef _FFR_PARSE_TIME
	time_t			dkim_msgdate;
#endif /* _FFR_PARSE_TIME */
	dkim_query_t		dkim_querymethod;
	dkim_canon_t		dkim_hdrcanonalg;
	dkim_canon_t		dkim_bodycanonalg;
	dkim_alg_t		dkim_signalg;
	off_t			dkim_bodylen;
	off_t			dkim_signlen;
	const char *		dkim_id;
	u_char *		dkim_domain;
	u_char *		dkim_user;
	u_char *		dkim_selector;
	u_char *		dkim_b64key;
	u_char *		dkim_b64sig;
	u_char *		dkim_key;
	u_char *		dkim_reportaddr;
	u_char *		dkim_sender;
	u_char *		dkim_signer;
	u_char *		dkim_error;
	u_char *		dkim_hdrlist;
	u_char *		dkim_zdecode;
	char *			dkim_tmpdir;
	DKIM_SIGINFO *		dkim_signature;
	void *			dkim_closure;
	const void *		dkim_user_context;
	struct dkim_siginfo **	dkim_siglist;
	struct dkim_set *	dkim_sethead;
	struct dkim_set *	dkim_settail;
	struct dkim_set *	dkim_sigset;
	struct dkim_header *	dkim_hhead;
	struct dkim_header *	dkim_htail;
	struct dkim_header *	dkim_senderhdr;
	struct dkim_canon *	dkim_canonhead;
	struct dkim_canon *	dkim_canontail;
	struct dkim_dstring *	dkim_hdrbuf;
	struct dkim_dstring *	dkim_canonbuf;
	struct dkim_test_dns_data * dkim_dnstesth;
	struct dkim_test_dns_data * dkim_dnstestt;
	DKIM_LIB *		dkim_libhandle;
};

/* struct dkim_lib -- a DKIM library context */
struct dkim_lib
{
	_Bool			dkiml_signre;
	_Bool			dkiml_skipre;
#ifdef USE_UNBOUND
	_Bool			dkiml_ub_poller;
#endif /* USE_UNBOUND */
	u_int			dkiml_flags;
	u_int			dkiml_timeout;
	u_int			dkiml_version;
	u_int			dkiml_callback_int;
	time_t			dkiml_fixedtime;
	unsigned long		dkiml_sigttl;
	unsigned long		dkiml_clockdrift;
	dkim_query_t		dkiml_querymethod;
	void *			(*dkiml_malloc) (void *closure, size_t nbytes);
	void			(*dkiml_free) (void *closure, void *p);
#if USE_ARLIB
	AR_LIB			dkiml_arlib;
# ifdef _FFR_DNS_UPGRADE
	AR_LIB			dkiml_arlibtcp;
# endif /* _FFR_DNS_UPGRADE */
#endif /* USE_ARLIB */
	u_char **		dkiml_senderhdrs;
	u_char **		dkiml_alwayshdrs;
	u_char **		dkiml_mbs;
#ifdef QUERY_CACHE
	DB *			dkiml_cache;
#endif /* QUERY_CACHE */
	regex_t			dkiml_hdrre;
	regex_t			dkiml_skiphdrre;
#ifdef USE_UNBOUND
	struct ub_ctx *		dkiml_unbound_ctx;
	pthread_mutex_t		dkiml_ub_lock;
	pthread_cond_t		dkiml_ub_ready;
#endif /* USE_UNBOUND */
	DKIM_CBSTAT		(*dkiml_key_lookup) (DKIM *dkim,
				                     DKIM_SIGINFO *sig,
				                     u_char *buf,
				                     size_t buflen);
	DKIM_CBSTAT		(*dkiml_policy_lookup) (DKIM *dkim,
				                        u_char *query,
				                        _Bool excheck,
				                        u_char *buf,
				                        size_t buflen,
				                        int *qstat);
	void *			(*dkiml_sig_handle) (void *closure);
	void			(*dkiml_sig_handle_free) (void *closure,
				                          void *user);
	void			(*dkiml_sig_tagvalues) (void *user,
				                        dkim_param_t pcode,
				                        const u_char *param,
				                        const u_char *value);
	DKIM_CBSTAT		(*dkiml_prescreen) (DKIM *dkim,
				                    DKIM_SIGINFO **sigs,
				                    int nsigs);
	DKIM_CBSTAT		(*dkiml_final) (DKIM *dkim,
				                DKIM_SIGINFO **sigs,
				                int nsigs);
	void			(*dkiml_dns_callback) (const void *context);
	u_char			dkiml_tmpdir[MAXPATHLEN + 1];
	u_char			dkiml_queryinfo[MAXPATHLEN + 1];
};

#endif /* _DKIM_TYPES_H_ */
