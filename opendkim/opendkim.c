/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2015, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS
#endif /* ! _POSIX_PTHREAD_SEMANTICS */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef HAVE_ISO_LIMITS_ISO_H
# include <iso/limits_iso.h>
#endif /* HAVE_ISO_LIMITS_ISO_H */
#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif /* HAVE_LIMITS_H */
#ifdef __linux__
# include <sys/prctl.h>
#endif /* __linux__ */
#ifdef USE_LUA
# include <netinet/in.h>
# include <arpa/inet.h>
#endif /* USE_LUA */
#ifdef AF_INET6
# include <arpa/inet.h>
#endif /* AF_INET6 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <math.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <regex.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#else /* USE_GNUTLS */
# include <openssl/sha.h>
# include <openssl/err.h>
#endif /* USE_GNUTLS */

#ifndef SHA_DIGEST_LENGTH
# define SHA_DIGEST_LENGTH 20
#endif /* ! SHA_DIGEST_LENGTH */

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif /* ! _PATH_DEVNULL */

/* libmilter includes */
#include "libmilter/mfapi.h"

#ifdef USE_LUA
/* LUA includes */
# include <lua.h>
#endif /* USE_LUA */

#ifdef _FFR_RBL
/* librbl includes */
# include <rbl.h>
#endif /* _FFR_RBL */

/* libopendkim includes */
#include "dkim.h"
#ifdef _FFR_VBR
# include "vbr.h"
#endif /* _FFR_VBR */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

#ifdef _FFR_REPUTATION
/* reputation includes */
# include <repute.h>
#endif /* _FFR_REPUTATION */

#ifdef _FFR_REPRRD
# include <reprrd.h>
#endif /* _FFR_REPRRD */

/* opendkim includes */
#include "config.h"
#ifdef _FFR_RATE_LIMIT
# include "flowrate.h"
#endif /* _FFR_RATE_LIMIT */
#include "opendkim-db.h"
#include "opendkim-config.h"
#include "opendkim-crypto.h"
#include "opendkim.h"
#include "opendkim-ar.h"
#include "opendkim-arf.h"
#include "opendkim-dns.h"
#ifdef USE_LUA
# include "opendkim-lua.h"
#endif /* USE_LUA */
#include "util.h"
#include "test.h"
#ifdef _FFR_STATS
# include "stats.h"
#endif /* _FFR_STATS */
#ifdef _FFR_REPUTATION
# include "reputation.h"
#endif /* _FFR_REPUTATION */

/* macros */
#define CMDLINEOPTS	"Ab:c:d:De:fF:k:lL:no:p:P:Qrs:S:t:T:u:vVWx:X?"

#ifndef MIN
# define MIN(x,y)	((x) < (y) ? (x) : (y))
#endif /* ! MIN */

#define	DKIMF_MILTER_ACCEPT	0
#define	DKIMF_MILTER_REJECT	1
#define	DKIMF_MILTER_TEMPFAIL	2
#define	DKIMF_MILTER_DISCARD	3
#define	DKIMF_MILTER_QUARANTINE	4

/*
**  ADDRLIST -- address list
*/

struct addrlist
{
	char *		a_addr;			/* address */
	struct addrlist * a_next;		/* next record */
};

/*
**  HANDLING -- message handling requests
*/

struct handling
{
	int		hndl_nosig;		/* no signature */
	int		hndl_badsig;		/* bad signature */
	int		hndl_nokey;		/* no key in DNS */
	int		hndl_dnserr;		/* DNS error */
	int		hndl_internal;		/* internal error */
#if defined(_FFR_REPUTATION) || defined(_FFR_REPRRD)
	int		hndl_reperr;		/* reputation error */
#endif /* _FFR_REPUTATION || _FFR_REPRRD */
	int		hndl_security;		/* security concerns */
	int		hndl_siggen;		/* sig generation errors */
};

struct handling defaults =
{
	DKIMF_MILTER_ACCEPT,			/* nosig */
	DKIMF_MILTER_ACCEPT,			/* badsig */
	DKIMF_MILTER_ACCEPT,			/* nokey */
	DKIMF_MILTER_TEMPFAIL,			/* dnserr */
	DKIMF_MILTER_TEMPFAIL,			/* internal */
#ifdef _FFR_REPUTATION
	DKIMF_MILTER_ACCEPT,			/* reperror */
#endif /* _FFR_REPUTATION */
	DKIMF_MILTER_TEMPFAIL,			/* security */
	DKIMF_MILTER_REJECT			/* siggen */
};

/*
**  LUA_GLOBAL -- linked list of Lua globals
*/

struct lua_global
{
	int		lg_type;
	char *		lg_name;
	void *		lg_value;
	struct lua_global * lg_next;
};

/*
**  CONFIG -- configuration data
*/

struct dkimf_config
{
	_Bool		conf_disablecryptoinit;	/* initialize SSL libs? */
#if defined(USE_LDAP) || defined(USE_ODBX)
	_Bool		conf_softstart;		/* do LDAP/SQL soft starts */
#endif /* defined(USE_LDAP) || defined(USE_ODBX) */
#ifdef _FFR_LUA_ONLY_SIGNING
	_Bool		conf_luasigning;	/* signing via Lua only */
#endif /* _FFR_LUA_ONLY_SIGNING */
	_Bool		conf_weaksyntax;	/* do weaker syntax checking */
	_Bool		conf_passmalformed;	/* pass malformed messages */
	_Bool		conf_logresults;	/* log all results */
	_Bool		conf_dnsconnect;	/* request TCP mode from DNS */
	_Bool		conf_capture;		/* capture unknown errors */
	_Bool		conf_restrace;		/* resolver tracing? */
	_Bool		conf_acceptdk;		/* accept DK keys? */
	_Bool		conf_addswhdr;		/* add identifying header? */
	_Bool		conf_blen;		/* use "l=" when signing */
	_Bool		conf_ztags;		/* use "z=" when signing */
	_Bool		conf_alwaysaddar;	/* always add Auth-Results:? */
	_Bool		conf_reqreports;	/* request reports */
	_Bool		conf_sendreports;	/* signature failure reports */
	_Bool		conf_reqhdrs;		/* required header checks */
	_Bool		conf_authservidwithjobid; /* use jobids in A-R headers */
	_Bool		conf_subdomains;	/* sign subdomains */
	_Bool		conf_remsigs;		/* remove current signatures? */
	_Bool		conf_remarall;		/* remove all matching ARs? */
	_Bool		conf_keepar;		/* keep our ARs? */
	_Bool		conf_dolog;		/* syslog interesting stuff? */
	_Bool		conf_dolog_success;	/* syslog successes too? */
	_Bool		conf_milterv2;		/* using milter v2? */
	_Bool		conf_fixcrlf;		/* fix bare CRs and LFs? */
	_Bool		conf_logwhy;		/* log mode decision logic */
	_Bool		conf_allowsha1only;	/* allow rsa-sha1 verifying */
	_Bool		conf_stricthdrs;	/* strict header checks */
	_Bool		conf_keeptmpfiles;	/* keep temporary files */
	_Bool		conf_multisig;		/* multiple signatures */
	_Bool		conf_enablecores;	/* enable coredumps */
	_Bool		conf_noheaderb;		/* suppress "header.b" */
	_Bool		conf_singleauthres;	/* single Auth-Results */
	_Bool		conf_safekeys;		/* check key permissions */
#ifdef _FFR_RESIGN
	_Bool		conf_resignall;		/* resign unverified mail */
#endif /* _FFR_RESIGN */
#ifdef USE_LDAP
	_Bool		conf_ldap_usetls;	/* LDAP TLS */
#endif /* USE_LDAP */
#ifdef _FFR_VBR
	_Bool		conf_vbr_purge;		/* purge X-VBR-* fields */
	_Bool		conf_vbr_trustedonly;	/* trusted certifiers only */
#endif /* _FFR_VBR */
#if defined(_FFR_REPUTATION) || defined(_FFR_REPRRD)
	_Bool		conf_reptest;		/* reputation test mode */
	_Bool		conf_repverbose;	/* verbose reputation logs */
#endif /* _FFR_REPUTATION || _FFR_REPRRD */
	unsigned int	conf_mode;		/* operating mode */
	unsigned int	conf_refcnt;		/* reference count */
	unsigned int	conf_dnstimeout;	/* DNS timeout */
	unsigned int	conf_maxhdrsz;		/* max header bytes */
	unsigned int	conf_maxverify;		/* max sigs to verify */
	unsigned int	conf_minkeybits;	/* min key size (bits) */
#ifdef _FFR_REPUTATION
	unsigned int	conf_repfactor;		/* reputation factor */
	unsigned int	conf_repminimum;	/* reputation minimum */
	unsigned int	conf_repcachettl;	/* reputation cache TTL */
	unsigned int	conf_reptimeout;	/* reputation query timeout */
#endif /* _FFR_REPUTATION */
#ifdef USE_UNBOUND
	unsigned int	conf_boguskey;		/* bogus key action */
	unsigned int	conf_unprotectedkey;	/* unprotected key action */
#endif /* USE_UNBOUND */
#ifdef _FFR_RATE_LIMIT
	unsigned int	conf_flowdatattl;	/* flow data TTL */
	unsigned int	conf_flowfactor;	/* flow factor */
#endif /* _FFR_RATE_LIMIT */
	int		conf_clockdrift;	/* tolerable clock drift */
	int		conf_sigmintype;	/* signature minimum type */
	size_t		conf_sigmin;		/* signature minimum */
	size_t		conf_keylen;		/* size of secret key */
#ifdef USE_LUA
	size_t		conf_screenfuncsz;	/* screening function size */
	size_t		conf_setupfuncsz;	/* setup function size */
# ifdef _FFR_STATS
	size_t		conf_statsfuncsz;	/* stats function size */
# endif /* _FFR_STATS */
	size_t		conf_finalfuncsz;	/* final function size */
#endif /* USE_LUA */
	ssize_t		conf_signbytes;		/* bytes to sign */
	dkim_canon_t 	conf_hdrcanon;		/* canon. method for headers */
	dkim_canon_t 	conf_bodycanon;		/* canon. method for body */
	unsigned long	conf_sigttl;		/* signature TTLs */
	dkim_alg_t	conf_signalg;		/* signing algorithm */
	struct config *	conf_data;		/* configuration data */
#ifdef HAVE_CURL_EASY_STRERROR
	char *		conf_smtpuri;		/* outgoing mail URI */
#endif /* HAVE_CURL_EASY_STRERROR */
	char *		conf_authservid;	/* authserv-id */
	char *		conf_keyfile;		/* key file for single key */
	char *		conf_keytable;		/* key table */
	char *		conf_signtable;		/* signing table */
	char *		conf_peerfile;		/* peer file */
	char *		conf_internalfile;	/* internal hosts file */
	char *		conf_externalfile;	/* external hosts file */
	char *		conf_exemptfile;	/* exempt domains file */
	char *		conf_tmpdir;		/* temp directory */
	char *		conf_omitlist;		/* omit header list */
	char *		conf_domlist;		/* signing domain list */
	char *		conf_signalgstr;	/* signature algorithm string */
	char *		conf_modestr;		/* mode string */
	char *		conf_canonstr;		/* canonicalization(s) string */
	char *		conf_siglimit;		/* signing limits */
	char *		conf_chroot;		/* chroot(2) directory */
	char *		conf_selectcanonhdr;	/* canon select header name */
	u_char *	conf_selector;		/* key selector */
#ifdef _FFR_DEFAULT_SENDER
	char *		conf_defsender;		/* default sender address */
#endif /* _FFR_DEFAULT_SENDER */
#ifdef _FFR_RESIGN
	char *		conf_resign;		/* resign mail to */
#endif /* _FFR_RESIGN */
#ifdef _FFR_SENDER_MACRO
	char *		conf_sendermacro;	/* macro containing sender */
#endif /* _FFR_SENDER_MACRO */
	char *		conf_testdnsdata;	/* test DNS data */
#ifdef _FFR_IDENTITY_HEADER
	char *		conf_identityhdr;	/* identity header */
	_Bool		conf_rmidentityhdr;	/* remove identity header */
#endif /* _FFR_IDENTITY_HEADER */
	char *		conf_diagdir;		/* diagnostics directory */
#ifdef _FFR_STATS
	char *		conf_statspath;		/* path for stats file */
	char *		conf_reporthost;	/* reporter name */
	char *		conf_reportprefix;	/* stats data prefix */
#endif /* _FFR_STATS */
	char *		conf_reportaddr;	/* report sender address */
	char *		conf_reportaddrbcc;	/* report repcipient address as bcc */
	char *		conf_mtacommand;	/* MTA command (reports) */
	char *		conf_redirect;		/* redirect failures to */
#ifdef USE_LDAP
	char *		conf_ldap_timeout;	/* LDAP timeout */
	char *		conf_ldap_kaidle;	/* LDAP keepalive idle */
	char *		conf_ldap_kaprobes;	/* LDAP keepalive probes */
	char *		conf_ldap_kainterval;	/* LDAP keepalive interval */
	char *		conf_ldap_binduser;	/* LDAP bind user */
	char *          conf_ldap_bindpw;	/* LDAP bind password */
	char *          conf_ldap_authmech;	/* LDAP auth mechanism */
# ifdef USE_SASL
	char *		conf_ldap_authname;	/* LDAP auth name */
	char *		conf_ldap_authuser;	/* LDAP auth user */
	char *		conf_ldap_authrealm;	/* LDAP auth realm */
# endif /* USE_SASL */
#endif /* USE_LDAP */
#ifdef USE_LUA
	char *		conf_screenscript;	/* Lua script: screening */
	void *		conf_screenfunc;	/* Lua function: screening */
	char *		conf_setupscript;	/* Lua script: setup */
	void *		conf_setupfunc;		/* Lua function: setup */
# ifdef _FFR_STATSEXT
	char *		conf_statsscript;	/* Lua script: stats */
	void *		conf_statsfunc;		/* Lua function: stats */
# endif /* _FFR_STATSEXT */
	char *		conf_finalscript;	/* Lua script: final */
	void *		conf_finalfunc;		/* Lua function: final */
#endif /* USE_LUA */
#ifdef _FFR_REPLACE_RULES
	char *		conf_rephdrs;		/* replacement headers */
	struct replace * conf_replist;		/* replacement list */
	DKIMF_DB	conf_rephdrsdb;		/* replacement headers (DB) */
#endif /* _FFR_REPLACE_RULES */
	dkim_sigkey_t	conf_seckey;		/* secret key data */
	char *		conf_nslist;		/* replacement NS list */
	char *		conf_trustanchorpath;	/* trust anchor file */
	char *		conf_resolverconfig;	/* resolver config file */
#ifdef _FFR_VBR
	char *		conf_vbr_deftype;	/* default VBR type */
	char *		conf_vbr_defcert;	/* default VBR certifiers */
	DKIMF_DB	conf_vbr_trusteddb;	/* trusted certifiers (DB) */
	u_char **	conf_vbr_trusted;	/* trusted certifiers */
#endif /* _FFR_VBR */
	DKIMF_DB	conf_testdnsdb;		/* test TXT records */
	DKIMF_DB	conf_bldb;		/* l= recipients (DB) */
	DKIMF_DB	conf_domainsdb;		/* domains to sign (DB) */
	DKIMF_DB	conf_omithdrdb;		/* headers to omit (DB) */
	char **		conf_omithdrs;		/* headers to omit (array) */
	DKIMF_DB	conf_signhdrsdb;	/* headers to sign (DB) */
	char **		conf_signhdrs;		/* headers to sign (array) */
	DKIMF_DB	conf_senderhdrsdb;	/* sender headers (DB) */
	char **		conf_senderhdrs;	/* sender headers (array) */
	DKIMF_DB	conf_mtasdb;		/* MTA ports to sign (DB) */
	char **		conf_mtas;		/* MTA ports to sign (array) */
	DKIMF_DB	conf_remardb;		/* A-R removal list (DB) */
	char **		conf_remar;		/* A-R removal list (array) */
	DKIMF_DB	conf_mbsdb;		/* must-be-signed hdrs (DB) */
	char **		conf_mbs;		/* must-be-signed (array) */
	DKIMF_DB	conf_oversigndb;	/* fields to over-sign (DB) */
	char **		conf_oversignhdrs;	/*   "    "     "    (array) */
	DKIMF_DB	conf_dontsigntodb;	/* don't-sign-to addrs (DB) */
#ifdef _FFR_ATPS
	DKIMF_DB	conf_atpsdb;		/* ATPS domains */
	char *		conf_atpshash;		/* ATPS hash algorithm */
#endif /* _FFR_ATPS */
	DKIMF_DB	conf_thirdpartydb;	/* trustsigsfrom DB */
	DKIMF_DB	conf_macrosdb;		/* macros/values (DB) */
	char **		conf_macros;		/* macros/values to check */
	regex_t **	conf_nosignpats;	/* do-not-sign patterns */
	DKIMF_DB	conf_peerdb;		/* DB of "peers" */
	DKIMF_DB	conf_internal;		/* DB of "internal" hosts */
	DKIMF_DB	conf_exignore;		/* "external ignore" host DB */
	DKIMF_DB	conf_exemptdb;		/* exempt domains DB */
	DKIMF_DB	conf_keytabledb;	/* key table DB */
	DKIMF_DB	conf_signtabledb;	/* signing table DB */
#ifdef _FFR_STATS
	DKIMF_DB	conf_anondb;		/* anonymized domains DB */
#endif /* _FFR_STATS */
#ifdef _FFR_RESIGN
	DKIMF_DB	conf_resigndb;		/* resigning addresses */
#endif /* _FFR_RESIGN */
#ifdef _FFR_RATE_LIMIT
	DKIMF_DB	conf_ratelimitdb;	/* domain rate limits */
	DKIMF_DB	conf_flowdatadb;	/* domain flow data */
#endif /* _FFR_RATE_LIMIT */
#ifdef _FFR_REPUTATION
	char *		conf_repratios;		/* reputed ratios */
	DKIMF_DB	conf_repratiosdb;	/* reputed ratios DB */
	char *		conf_replimits;		/* reputed limits */
	DKIMF_DB	conf_replimitsdb;	/* reputed limits DB */
	char *		conf_replimitmods;	/* reputed limit modifiers */
	DKIMF_DB	conf_replimitmodsdb;	/* reputed limit mods DB */
	char *		conf_replowtime;	/* reputed low timers */
	DKIMF_DB	conf_replowtimedb;	/* reputed low timers DB */
	DKIMF_REP	conf_rep;		/* reputation subsystem */
	char *		conf_repcache;		/* reputation cache DB */
	char *		conf_repdups;		/* reputation duplicates DB */
	char *		conf_repspamcheck;	/* reputation spam RE string */
	regex_t		conf_repspamre;		/* reputation spam RE */
#endif /* _FFR_REPUTATION */
#ifdef _FFR_REPRRD
	REPRRD		conf_reprrd;		/* reputation RRD handle */
#endif /* _FFR_REPRRD */
	DKIM_LIB *	conf_libopendkim;	/* DKIM library handle */
	struct handling	conf_handling;		/* message handling */
};

/*
**  MSGCTX -- message context, containing transaction-specific data
*/

typedef struct msgctx * msgctx;
struct msgctx
{
	_Bool		mctx_internal;		/* internal source? */
	_Bool		mctx_bldbdone;		/* BodyLengthDB applied? */
	_Bool		mctx_eom;		/* in EOM? (enables progress) */
	_Bool		mctx_addheader;		/* Authentication-Results: */
	_Bool		mctx_headeronly;	/* in EOM, only add headers */
	_Bool		mctx_ltag;		/* sign with l= tag? */
	_Bool		mctx_capture;		/* capture message? */
	_Bool		mctx_susp;		/* suspicious message? */
#ifdef _FFR_RESIGN
	_Bool		mctx_resign;		/* arrange to re-sign */
#endif /* _FFR_RESIGN */
#ifdef _FFR_VBR
	_Bool		mctx_vbrpurge;		/* purge X-VBR-* headers */
#endif /* _FFR_VBR */
#ifdef _FFR_REPUTATION
	_Bool		mctx_spam;		/* is spam? */
#endif /* _FFR_REPUTATION */
#ifdef _FFR_ATPS
	int		mctx_atps;		/* ATPS */
#endif /* _FFR_ATPS */
#ifdef USE_LUA
	int		mctx_mresult;		/* SMFI status code */
#endif /* USE_LUA */
	int		mctx_status;		/* status to report back */
	dkim_canon_t	mctx_hdrcanon;		/* header canonicalization */
	dkim_canon_t	mctx_bodycanon;		/* body canonicalization */
	dkim_alg_t	mctx_signalg;		/* signature algorithm */
#ifdef USE_UNBOUND
	int		mctx_dnssec_key;	/* DNSSEC results for key */
#endif /* USE_UNBOUND */
	int		mctx_queryalg;		/* query algorithm */
	int		mctx_hdrbytes;		/* header space allocated */
	struct dkimf_dstring * mctx_tmpstr;	/* temporary string */
	u_char *	mctx_jobid;		/* job ID */
	u_char *	mctx_laddr;		/* address triggering l= */
	DKIM *		mctx_dkimv;		/* verification handle */
#ifdef _FFR_VBR
	VBR *		mctx_vbr;		/* VBR handle */
	char *		mctx_vbrinfo;		/* VBR-Info header field */
#endif /* _FFR_VBR */
	struct Header *	mctx_hqhead;		/* header queue head */
	struct Header *	mctx_hqtail;		/* header queue tail */
	struct signreq * mctx_srhead;		/* signature request head */
	struct signreq * mctx_srtail;		/* signature request tail */
	struct addrlist * mctx_rcptlist;	/* recipient list */
#ifdef _FFR_STATSEXT
	struct statsext * mctx_statsext;	/* extension stats list */
#endif /* _FFR_STATSEXT */
	struct lua_global * mctx_luaglobalh;	/* Lua global list */
	struct lua_global * mctx_luaglobalt;	/* Lua global list */
#ifdef _FFR_REPUTATION
# ifdef USE_GNUTLS
	gnutls_hash_hd_t mctx_hash;			/* hash, for dup detection */
# else /* USE_GNUTLS */
	SHA_CTX		mctx_hash;		/* hash, for dup detection */
# endif /* USE_GNUTLS */
#endif /* _FFR_REPUTATION */
	unsigned char	mctx_envfrom[MAXADDRESS + 1];
						/* envelope sender */
	unsigned char	mctx_domain[DKIM_MAXHOSTNAMELEN + 1];
						/* primary domain */
	unsigned char	mctx_dkimar[DKIM_MAXHEADER + 1];
						/* DKIM Auth-Results content */
};

/*
**  CONNCTX -- connection context, containing thread-specific data
*/

typedef struct connctx * connctx;
struct connctx
{
	_Bool		cctx_milterv2;		/* milter v2 available */
	_Bool		cctx_noleadspc;		/* no leading spaces */
	char		cctx_host[DKIM_MAXHOSTNAMELEN + 1];
						/* hostname */
	struct sockaddr_storage	cctx_ip;	/* IP info */
	struct dkimf_config * cctx_config;	/* configuration in use */
	struct msgctx *	cctx_msg;		/* message context */
};

/*
**  LOOKUP -- lookup table
*/

struct lookup
{
	char *		str;
	int		code;
};

#define	HNDL_DEFAULT		0
#define	HNDL_NOSIGNATURE	1
#define	HNDL_BADSIGNATURE	2
#define	HNDL_DNSERROR		3
#define	HNDL_INTERNAL		4
#define	HNDL_SECURITY		5
#define	HNDL_NOKEY		6
#define	HNDL_POLICYERROR	7
#define	HNDL_REPERROR		8
#define	HNDL_SIGGEN		9

#define	DKIMF_MODE_SIGNER	0x01
#define	DKIMF_MODE_VERIFIER	0x02
#define	DKIMF_MODE_DEFAULT	(DKIMF_MODE_SIGNER|DKIMF_MODE_VERIFIER)

#define	DKIMF_STATUS_GOOD	0
#define	DKIMF_STATUS_BAD	1
#define	DKIMF_STATUS_NOKEY	2
#define	DKIMF_STATUS_REVOKED	3
#define	DKIMF_STATUS_NOSIGNATURE 4
#define	DKIMF_STATUS_BADFORMAT	5
#define	DKIMF_STATUS_PARTIAL	6
#define	DKIMF_STATUS_VERIFYERR	7
#define	DKIMF_STATUS_UNKNOWN	8

#define SIGMIN_BYTES		0
#define SIGMIN_PERCENT		1
#define SIGMIN_MAXADD		2

#if defined(_FFR_REPUTATION) || defined(_FFR_REPRRD)
# define REPDENYSMTP		"450"
# define REPDENYESC		"4.7.1"
# define REPDENYTXT		"Message deferred for policy reasons"
#endif /* _FFR_REPUTATION || _FFR_REPRRD */

#define	DELIMITER		"\001"

struct lookup dkimf_params[] =
{
	{ "badsignature",	HNDL_BADSIGNATURE },
	{ "default",		HNDL_DEFAULT },
	{ "dnserror",		HNDL_DNSERROR },
	{ "internalerror",	HNDL_INTERNAL },
	{ "keynotfound",	HNDL_NOKEY },
	{ "nosignature",	HNDL_NOSIGNATURE },
#ifdef _FFR_REPUTATION
	{ "reputationerror",	HNDL_REPERROR },
#endif /* _FFR_REPUTATION */
	{ "security",		HNDL_SECURITY },
	{ "signatureerror",	HNDL_SIGGEN },
	{ NULL,			-1 },
};

struct lookup dkimf_values[] =
{
	{ "a",			DKIMF_MILTER_ACCEPT },
	{ "accept",		DKIMF_MILTER_ACCEPT },
	{ "d",			DKIMF_MILTER_DISCARD },
	{ "discard",		DKIMF_MILTER_DISCARD },
#ifdef SMFIF_QUARANTINE
	{ "q",			DKIMF_MILTER_QUARANTINE },
	{ "quarantine",		DKIMF_MILTER_QUARANTINE },
#endif /* SMFIF_QUARANTINE */
	{ "r",			DKIMF_MILTER_REJECT },
	{ "reject",		DKIMF_MILTER_REJECT },
	{ "t",			DKIMF_MILTER_TEMPFAIL },
	{ "tempfail",		DKIMF_MILTER_TEMPFAIL },
	{ NULL,			-1 },
};

struct lookup dkimf_canon[] =
{
	{ "relaxed",		DKIM_CANON_RELAXED },
	{ "simple",		DKIM_CANON_SIMPLE },
	{ NULL,			-1 },
};

struct lookup dkimf_sign[] =
{
	{ "rsa-sha1",		DKIM_SIGN_RSASHA1 },
	{ "rsa-sha256",		DKIM_SIGN_RSASHA256 },
	{ NULL,			-1 },
};

struct lookup dkimf_atpshash[] =
{
#ifdef HAVE_SHA256
	{ "sha256",		1 },
#endif /* HAVE_SHA256 */
	{ "sha1",		1 },
	{ "none",		1 },
	{ NULL,			-1 },
};

struct lookup log_facilities[] =
{
	{ "auth",		LOG_AUTH },
	{ "cron",		LOG_CRON },
	{ "daemon",		LOG_DAEMON },
	{ "kern",		LOG_KERN },
	{ "lpr",		LOG_LPR },
	{ "mail",		LOG_MAIL },
	{ "news",		LOG_NEWS },
	{ "security",		LOG_AUTH },       /* DEPRECATED */
	{ "syslog",		LOG_SYSLOG },
	{ "user",		LOG_USER },
	{ "uucp",		LOG_UUCP },
	{ "local0",		LOG_LOCAL0 },
	{ "local1",		LOG_LOCAL1 },
	{ "local2",		LOG_LOCAL2 },
	{ "local3",		LOG_LOCAL3 },
	{ "local4",		LOG_LOCAL4 },
	{ "local5",		LOG_LOCAL5 },
	{ "local6",		LOG_LOCAL6 },
	{ "local7",		LOG_LOCAL7 },
	{ NULL,			-1 }
};

#ifdef USE_UNBOUND
# define DKIMF_KEYACTIONS_NONE	0
# define DKIMF_KEYACTIONS_NEUTRAL 1
# define DKIMF_KEYACTIONS_FAIL	2

struct lookup dkimf_keyactions[] =
{
	{ "none",		DKIMF_KEYACTIONS_NONE },
	{ "neutral",		DKIMF_KEYACTIONS_NEUTRAL },
	{ "fail",		DKIMF_KEYACTIONS_FAIL },
	{ NULL,			-1 },
};
#endif /* USE_UNBOUND */

struct lookup dkimf_statusstrings[] =
{
	{ "no error",				DKIMF_STATUS_GOOD },
	{ "bad signature",			DKIMF_STATUS_BAD },
	{ "key retrieval failed",		DKIMF_STATUS_NOKEY },
	{ "key revoked",			DKIMF_STATUS_REVOKED },
	{ "no signature",			DKIMF_STATUS_NOSIGNATURE },
	{ "bad message/signature format",	DKIMF_STATUS_BADFORMAT },
	{ "invalid partial signature",		DKIMF_STATUS_PARTIAL },
	{ "verification error",			DKIMF_STATUS_VERIFYERR },
	{ "unknown error",			DKIMF_STATUS_UNKNOWN },
	{ NULL,					-1 }
};

/* PROTOTYPES */
#ifdef LEAK_TRACKING
void dkimf_debug_free __P((void *, char *, int));
void *dkim_debug_malloc __P((size_t, char *, int));
void *dkim_debug_realloc __P((void *, size_t, char *, int));

# define free(x)	dkimf_debug_free((x), __FILE__, __LINE__)
# define malloc(x)	dkimf_debug_malloc((x), __FILE__, __LINE__)
# define realloc(x,y)	dkimf_debug_realloc((x), (y), __FILE__, __LINE__)
#endif /* LEAK_TRACKING */

sfsistat mlfi_abort __P((SMFICTX *));
sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
sfsistat mlfi_close __P((SMFICTX *));
sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
sfsistat mlfi_envfrom __P((SMFICTX *, char **));
sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
sfsistat mlfi_eoh __P((SMFICTX *));
sfsistat mlfi_eom __P((SMFICTX *));
sfsistat mlfi_header __P((SMFICTX *, char *, char *));
sfsistat mlfi_negotiate __P((SMFICTX *, unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long *, unsigned long *,
                                        unsigned long *, unsigned long *));

static int dkimf_add_signrequest __P((struct msgctx *, DKIMF_DB,
                                      char *, char *, ssize_t));
sfsistat dkimf_addheader __P((SMFICTX *, char *, char *));
sfsistat dkimf_addrcpt __P((SMFICTX *, char *));
static int dkimf_apply_signtable __P((struct msgctx *, DKIMF_DB, DKIMF_DB,
                                      unsigned char *, unsigned char *, char *,
                                      size_t, _Bool));
sfsistat dkimf_chgheader __P((SMFICTX *, char *, int, char *));
static void dkimf_cleanup __P((SMFICTX *));
static void dkimf_config_reload __P((void));
sfsistat dkimf_delrcpt __P((SMFICTX *, char *));
static Header dkimf_findheader __P((msgctx, char *, int));
void *dkimf_getpriv __P((SMFICTX *));
char *dkimf_getsymval __P((SMFICTX *, char *));
sfsistat dkimf_insheader __P((SMFICTX *, int, char *, char *));
sfsistat dkimf_quarantine __P((SMFICTX *, char *));
void dkimf_sendprogress __P((const void *));
sfsistat dkimf_setpriv __P((SMFICTX *, void *));
sfsistat dkimf_setreply __P((SMFICTX *, char *, char *, char *));
static void dkimf_sigreport __P((connctx, struct dkimf_config *, char *));

/* GLOBALS */
_Bool dolog;					/* logging? (exported) */
_Bool reload;					/* reload requested */
_Bool no_i_whine;				/* noted ${i} is undefined */
_Bool testmode;					/* test mode */
_Bool allowdeprecated;				/* allow deprecated config values */
#ifdef QUERY_CACHE
_Bool querycache;				/* local query cache */
#endif /* QUERY_CACHE */
_Bool die;					/* global "die" flag */
int diesig;					/* signal to distribute */
int thread_count;				/* thread count */
#ifdef QUERY_CACHE
time_t cache_lastlog;				/* last cache stats logged */
#endif /* QUERY_CACHE */
char *progname;					/* program name */
char *sock;					/* listening socket */
char *conffile;					/* configuration file */
struct dkimf_config *curconf;			/* current configuration */
#ifdef POPAUTH
DKIMF_DB popdb;					/* POP auth DB */
#endif /* POPAUTH */
char reportcmd[BUFRSZ + 1];			/* reporting command */
char reportaddr[MAXADDRESS + 1];		/* reporting address */
char myhostname[DKIM_MAXHOSTNAMELEN + 1];	/* hostname */
pthread_mutex_t conf_lock;			/* config lock */
pthread_mutex_t pwdb_lock;			/* passwd/group lock */

/* Other useful definitions */
#define CRLF			"\r\n"		/* CRLF */

/* MACROS */
#define	JOBID(x)	((x) == NULL ? JOBIDUNKNOWN : (char *) (x))
#define	TRYFREE(x)	do { \
				if ((x) != NULL) \
				{ \
					free(x); \
					(x) = NULL; \
				} \
			} while (0)
#define	DKIMF_EOHMACROS	"i {daemon_name} {auth_type}"



/*
**  ==================================================================
**  BEGIN private section
*/

#ifndef HAVE_SMFI_INSHEADER
/*
**  SMFI_INSHEADER -- stub for smfi_insheader() which didn't exist before
**                    sendmail 8.13.0
**
**  Parameters:
**  	ctx -- milter context
**  	idx -- insertion index
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat 
smfi_insheader(SMFICTX *ctx, int idx, char *hname, char *hvalue)
{
	assert(ctx != NULL);
	assert(hname != NULL);
	assert(hvalue != NULL);

	return smfi_addheader(ctx, hname, hvalue);
}
#endif /* ! HAVE_SMFI_INSHEADER */

/*
**  DKIMF_GETPRIV -- wrapper for smfi_getpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	The stored private pointer, or NULL.
*/

void *
dkimf_getpriv(SMFICTX *ctx)
{
	assert(ctx != NULL);

	if (testmode)
		return dkimf_test_getpriv((void *) ctx);
	else
		return smfi_getpriv(ctx);
}

/*
**  DKIMF_SETPRIV -- wrapper for smfi_setpriv()
**
**  Parameters:
**  	ctx -- milter (or test) context
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_setpriv(SMFICTX *ctx, void *ptr)
{
	assert(ctx != NULL);

	if (testmode)
		return dkimf_test_setpriv((void *) ctx, ptr);
	else
		return smfi_setpriv(ctx, ptr);
}

/*
**  DKIMF_INSHEADER -- wrapper for smfi_insheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	idx -- index at which to insert
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_insheader(SMFICTX *ctx, int idx, char *hname, char *hvalue)
{
	assert(ctx != NULL);
	assert(hname != NULL);
	assert(hvalue != NULL);

	if (testmode)
		return dkimf_test_insheader(ctx, idx, hname, hvalue);
	else
#ifdef HAVE_SMFI_INSHEADER
		return smfi_insheader(ctx, idx, hname, hvalue);
#else /* HAVE_SMFI_INSHEADER */
		return smfi_addheader(ctx, hname, hvalue);
#endif /* HAVE_SMFI_INSHEADER */
}

/*
**  DKIMF_CHGHEADER -- wrapper for smfi_chgheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	hname -- header name
**  	idx -- index of header to be changed
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_chgheader(SMFICTX *ctx, char *hname, int idx, char *hvalue)
{
	assert(ctx != NULL);
	assert(hname != NULL);

	if (testmode)
		return dkimf_test_chgheader(ctx, hname, idx, hvalue);
	else
		return smfi_chgheader(ctx, hname, idx, hvalue);
}

/*
**  DKIMF_QUARANTINE -- wrapper for smfi_quarantine()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	reason -- quarantine reason
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_quarantine(SMFICTX *ctx, char *reason)
{
	assert(ctx != NULL);

	if (testmode)
		return dkimf_test_quarantine(ctx, reason);
#ifdef SMFIF_QUARANTINE
	else
		return smfi_quarantine(ctx, reason);
#endif /* SMFIF_QUARANTINE */
}

/*
**  DKIMF_ADDHEADER -- wrapper for smfi_addheader()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	hname -- header name
**  	hvalue -- header value
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_addheader(SMFICTX *ctx, char *hname, char *hvalue)
{
	assert(ctx != NULL);
	assert(hname != NULL);
	assert(hvalue != NULL);

	if (testmode)
		return dkimf_test_addheader(ctx, hname, hvalue);
	else
		return smfi_addheader(ctx, hname, hvalue);
}

/*
**  DKIMF_ADDRCPT -- wrapper for smfi_addrcpt()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	addr -- address to add
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_addrcpt(SMFICTX *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (testmode)
		return dkimf_test_addrcpt(ctx, addr);
	else
		return smfi_addrcpt(ctx, addr);
}

/*
**  DKIMF_DELRCPT -- wrapper for smfi_delrcpt()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	addr -- address to delete
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_delrcpt(SMFICTX *ctx, char *addr)
{
	assert(ctx != NULL);
	assert(addr != NULL);

	if (testmode)
		return dkimf_test_delrcpt(ctx, addr);
	else
		return smfi_delrcpt(ctx, addr);
}

/*
**  DKIMF_SETREPLY -- wrapper for smfi_setreply()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	rcode -- SMTP reply code
**  	xcode -- SMTP enhanced status code
**  	replytxt -- reply text
**
**  Return value:
**  	An sfsistat.
*/

sfsistat
dkimf_setreply(SMFICTX *ctx, char *rcode, char *xcode, char *replytxt)
{
	assert(ctx != NULL);

	if (testmode)
		return dkimf_test_setreply(ctx, rcode, xcode, replytxt);
	else
		return smfi_setreply(ctx, rcode, xcode, replytxt);
}

/*
**  DKIMF_GETSYMVAL -- wrapper for smfi_getsymval()
**
**  Parameters:
**  	ctx -- milter (or test) context
**  	sym -- symbol to retrieve
**
**  Return value:
**  	Pointer to the value of the requested MTA symbol.
*/

char *
dkimf_getsymval(SMFICTX *ctx, char *sym)
{
	assert(ctx != NULL);
	assert(sym != NULL);

	if (testmode)
		return dkimf_test_getsymval(ctx, sym);
	else
		return smfi_getsymval(ctx, sym);
}

#ifdef USE_LUA
/*
**  LUA ACCESSOR FUNCTIONS
**
**  These are the C sides of the utility functions that will be made available
**  to users via Lua to write their own policy scripts.
**
**  NAMES:
**  	Should all start "dkimf_xs_" (for DKIM filter accessors)
**
**  PARAMETERS:
**  	Should all accept nothing more than a single Lua state handle.
**  	Lua accessor and utility functions are used to pull parameters off
**  	the stack.
**
**  RETURN VALUES:
**  	Should all return the number of things they want to return via
**  	the Lua stack.  Generally accessors return one thing, and utility
**  	functions either return a result or a Lua "nil", which means
**  	at least one thing is always returned.
**
**  STACK:
**  	All functions should first evaluate the stack to see that it's what
**  	they expect in terms of number and types of elements.  The first
**  	stack item should always be expected to be a "light user data"
**  	(handle pointer) to a (SMFICTX).  If there are no errors,
**  	collect all the values and pop them.  The context pointer may come in
**  	NULL, in which case the script is being called during configuration
**  	verification; if so, return an appropriate dummy value from your
**  	function, if applicable, such as the name of the function or 0 or
**  	something matching what the script would expect back from
**  	the function such that the rest of the test will complete.
*/

/*
**  DKIMF_IMPORT_GLOBALS -- add globals to a Lua state
**
**  Parameters:
**  	ctx -- filter context
**  	l -- Lua state
**
**  Return value:
**  	None.
*/

void
dkimf_import_globals(void *p, lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *mctx;
	struct lua_global *lg;

	if (p == NULL)
		return;

	ctx = (SMFICTX *) p;
	cc = (struct connctx *) dkimf_getpriv(ctx);
	mctx = cc->cctx_msg;

	lg = mctx->mctx_luaglobalh;
	while (lg != NULL)
	{
		switch (lg->lg_type)
		{
		  case LUA_TNIL:
			lua_pushnil(l);
			lua_setglobal(l, lg->lg_name);
			break;

		  case LUA_TNUMBER:
		  {
			lua_Number x;

			memcpy(&x, lg->lg_value, sizeof x);
			lua_pushnumber(l, x);
			lua_setglobal(l, lg->lg_name);
			break;
		  }

		  case LUA_TBOOLEAN:
			lua_pushboolean(l, (long) lg->lg_value);
			lua_setglobal(l, lg->lg_name);
			break;

		  case LUA_TSTRING:
			lua_pushstring(l, (char *) lg->lg_value);
			lua_setglobal(l, lg->lg_name);
			break;

		  default:
			assert(0);
		}

		lg = lg->lg_next;
	}
}

/*
**  DKIMF_XS_SIGNFOR -- sign as if the mail came from a specified user
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_signfor(lua_State *l)
{
	_Bool multi = FALSE;
	int top;
	int status;
	struct lua_global *lg;
	SMFICTX *ctx;
	unsigned char *user = NULL;
	unsigned char *domain = NULL;
	struct connctx *cc;
	struct msgctx *msg;
	struct dkimf_config *conf;
	char addr[MAXADDRESS + 1];
	char errkey[BUFRSZ + 1];

	top = lua_gettop(l);
	if (top != 2 && top != 3)
	{
		lua_pushstring(l,
		               "odkim.signfor(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_isuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         (top == 3 && !lua_isboolean(l, 3)))
	{
		lua_pushstring(l, "odkim.signfor(): invalid argument");
		lua_error(l);
	}

	lua_pop(l, top);

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	if (ctx == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	strlcpy(addr, lua_tostring(l, 2), sizeof addr);

	if (top == 3)
		multi = lua_toboolean(l, 3);

	cc = (struct connctx *) dkimf_getpriv(ctx);
	msg = cc->cctx_msg;
	conf = cc->cctx_config;

	if (conf->conf_signtabledb == NULL ||
	    conf->conf_keytabledb == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	status = dkim_mail_parse(addr, &user, &domain);
	if (status != 0 || user == NULL || domain == NULL)
	{
		lua_pushstring(l, "odkim.signfor(): can't parse address");
		lua_error(l);
	}

	status = dkimf_apply_signtable(msg, conf->conf_keytabledb,
	                               conf->conf_signtabledb,
	                               user, domain, errkey, sizeof errkey,
	                               multi);
	if (status == -2 || status == -3)
	{
		lua_pushfstring(l, "odkim.signfor(): error processing key '%s'",
		                errkey);
		lua_error(l);
	}
	else if (status == -1)
	{
		lua_pushstring(l, "odkim.signfor(): can't read signing table");
		lua_error(l);
	}
	else
	{
		lua_pushnumber(l, status);
		return 1;
	}
}

/*
**  DKIMF_XS_EXPORT -- export a global for use in later scripts
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_export(lua_State *l)
{
	int c;
	int top;
	int type;
	struct lua_global *lg;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *msg;

	top = lua_gettop(l);

	if (top < 3 || top % 2 != 1)
	{
		lua_pushstring(l,
		               "odkim.export(): incorrect argument count");
		lua_error(l);
	}

	for (c = 2; c < top; c += 2)
	{
		if (!lua_isstring(l, c) ||
		    (!lua_isnil(l, c + 1) &&
		     !lua_isstring(l, c + 1) &&
		     !lua_isnumber(l, c + 1) &&
		     !lua_isboolean(l, c + 1)))
		{
			lua_pushstring(l,
			               "odkim.export(): incorrect argument type");
			lua_error(l);
		}
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	if (ctx == NULL)
	{
		lua_pop(l, top);
		return 0;
	}
	cc = (struct connctx *) dkimf_getpriv(ctx);
	msg = cc->cctx_msg;

	for (c = 2; c < top; c += 2)
	{
		type = lua_type(l, c + 1);

		if (type != LUA_TNIL &&
		    type != LUA_TNUMBER &&
		    type != LUA_TBOOLEAN &&
		    type != LUA_TSTRING)
			continue;

		lg = (struct lua_global *) malloc(sizeof *lg);
		if (lg != NULL)
		{
			lg->lg_name = strdup(lua_tostring(l, c));
			if (lg->lg_name == NULL)
			{
				free(lg);
				continue;
			}

			lg->lg_type = type;

			lg->lg_next = NULL;

			if (msg->mctx_luaglobalh == NULL)
				msg->mctx_luaglobalh = lg;
			else
				msg->mctx_luaglobalt->lg_next = lg;

			msg->mctx_luaglobalt = lg;

			switch (lg->lg_type)
			{
			  case LUA_TNIL:
				lg->lg_value = NULL;
				break;

			  case LUA_TNUMBER:
				lg->lg_value = malloc(sizeof(lua_Number));
				if (lg->lg_value != NULL)
				{
					lua_Number x;

					x = lua_tonumber(l, c + 1);
					memcpy(lg->lg_value, &x, sizeof x);
				}
				break;

			  case LUA_TBOOLEAN:
				if (lua_toboolean(l, c + 1))
					lg->lg_value = (void *) 1;
				else
					lg->lg_value = (void *) 0;
				break;

			  case LUA_TSTRING:
				lg->lg_value = strdup(lua_tostring(l, c + 1));
				break;
			}
		}
	}

	lua_pop(l, top);

	return 0;
}

# ifdef _FFR_RBL
/*
**  DKIMF_XS_RBLCHECK -- do an RBL query
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_rblcheck(lua_State *l)
{
	_Bool found = FALSE;
	RBL_STAT status;
	uint32_t res;
	double timeout = -1.;
	double i;
	const char *query;
	const char *qroot = NULL;
	void *qh;
	RBL *rbl;
	SMFICTX *ctx;
	struct connctx *cc = NULL;
	struct dkimf_config *conf;
	struct timeval to;

	if (lua_gettop(l) < 3 || lua_gettop(l) > 4)
	{
		lua_pushstring(l,
		               "odkim.rbl_check(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_isuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isstring(l, 3) ||
	         (lua_gettop(l) == 4 && !lua_isnumber(l, 4)))
	{
		lua_pushstring(l,
		               "odkim.rbl_check(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	if (ctx != NULL)
		cc = (struct connctx *) dkimf_getpriv(ctx);
		
	query = lua_tostring(l, 2);
	qroot = lua_tostring(l, 3);
	if (lua_gettop(l) == 4)
		timeout = lua_tonumber(l, 4);
	lua_pop(l, lua_gettop(l));

	if (cc == NULL)
		return 0;

	conf = cc->cctx_config;

	rbl = rbl_init(NULL, NULL, NULL);
	if (rbl == NULL)
	{
		lua_pushstring(l,
		               "odkim.rbl_check(): can't create RBL handle");
		lua_error(l);
	}

#  ifdef USE_UNBOUND
	dkimf_rbl_unbound_setup(rbl);
#  endif /* USE_UNBOUND */

	if (conf->conf_nslist != NULL)
	{
		status = rbl_dns_nslist(rbl, conf->conf_nslist);
		if (status != DKIM_STAT_OK)
		{
			lua_pushstring(l,
			               "odkim.rbl_check(): can't set nameserver list");
			lua_error(l);
		}
	}

	if (conf->conf_trustanchorpath != NULL)
	{
		if (access(conf->conf_trustanchorpath, R_OK) != 0)
		{
			lua_pushfstring(l,
			                "odkim.rbl_check(): %s: access(): %s",
			                conf->conf_trustanchorpath,
			                strerror(errno));
			lua_error(l);
		}

		status = rbl_dns_trustanchor(rbl, conf->conf_trustanchorpath);
		if (status != DKIM_STAT_OK)
		{
			lua_pushstring(l,
			               "odkim.rbl_check(): can't set trust anchor");
			lua_error(l);
		}
	}

	if (conf->conf_resolverconfig != NULL)
	{
		status = rbl_dns_config(rbl, conf->conf_resolverconfig);
		if (status != DKIM_DNS_SUCCESS)
		{
			lua_pushstring(l,
			               "odkim.rbl_check(): can't configure resolver");
			lua_error(l);
		}
	}

	rbl_setdomain(rbl, (u_char *) qroot);

	status = rbl_query_start(rbl, (u_char *) query, &qh);
	if (status != RBL_STAT_OK)
	{
		rbl_close(rbl);
		lua_pushstring(l,
		               "odkim.rbl_check(): RBL query failed");
		lua_error(l);
	}

	to.tv_usec = modf(timeout, &i);
	to.tv_sec = (u_int) i;

	status = rbl_query_check(rbl, qh, timeout == -1. ? NULL : &to, &res);

	if (status != RBL_STAT_NOTFOUND &&
	    status != RBL_STAT_NOREPLY &&
	    status != RBL_STAT_FOUND)
		lua_pushstring(l, rbl_geterror(rbl));
	else if (status == RBL_STAT_FOUND)
		found = TRUE;

	rbl_close(rbl);

	if (status != RBL_STAT_NOTFOUND &&
	    status != RBL_STAT_NOREPLY &&
	    status != RBL_STAT_FOUND)
	{
		return 1;
	}
	else if (found)
	{
		lua_pushnumber(l, res >> 24);
		lua_pushnumber(l, (res >> 16) & 0xff);
		lua_pushnumber(l, (res >> 8) & 0xff);
		lua_pushnumber(l, res & 0xff);
		return 4;
	}
	else
	{
		return 0;
	}
}
# endif /* _FFR_RBL */

/*
**  DKIMF_XS_XTAG -- add an extension tag
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_xtag(lua_State *l)
{
	SMFICTX *ctx;
	const char *tag = NULL;
	const char *value = NULL;

	if (lua_gettop(l) != 3)
	{
		lua_pushstring(l,
		               "odkim.xtag(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_isuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isstring(l, 3))
	{
		lua_pushstring(l,
		               "odkim.xtag(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	tag = lua_tostring(l, 2);
	value = lua_tostring(l, 3);
	lua_pop(l, 3);

	if (ctx != NULL)
	{
		int n = 0;
		int status;
		struct connctx *cc;
		struct msgctx *dfc;
		struct signreq *sr;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		for (sr = dfc->mctx_srhead; sr != NULL; sr = sr->srq_next)
		{
			status = dkim_add_xtag(sr->srq_dkim, tag, value);
			if (status != DKIM_STAT_OK)
			{
				lua_pushnumber(l, -1);
				return 1;
			}

			n++;
		}

		lua_pushnumber(l, n);
		return 1;
	}
	else
	{
		lua_pushnumber(l, 0);
		return 1;
	}
}

/*
**  DKIMF_XS_PARSEFIELD -- parse an address field into its components
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_parsefield(lua_State *l)
{
	unsigned char *user = NULL;
	unsigned char *domain = NULL;
	unsigned char field[DKIM_MAXHEADER + 1];

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.parse_field(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_isstring(l, 1))
	{
		lua_pushstring(l,
		               "odkim.parse_field(): incorrect argument type");
		lua_error(l);
	}

	strlcpy(field, lua_tostring(l, 1), sizeof field);
	lua_pop(l, 1);

	if (field == NULL)
	{
		lua_pushnil(l);
		return 1;
	}
	else if (dkim_mail_parse(field, &user, &domain) != 0 ||
	         user == NULL || domain == NULL)
	{
		lua_pushnil(l);
		return 1;
	}
	else
	{
		lua_pushstring(l, user);
		lua_pushstring(l, domain);
		return 2;
	}
}

/*
**  DKIMF_XS_LOG -- log a string
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_log(lua_State *l)
{
	SMFICTX *ctx;
	const char *logstring;

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l, "odkim.log(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l, "odkim.log(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	logstring = lua_tostring(l, 2);
	lua_pop(l, 2);

	if (ctx != NULL)
	{
		struct connctx *cc;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		if (cc->cctx_config->conf_dolog)
			syslog(LOG_INFO, "%s", logstring);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_FROMDOMAIN -- retrieve From: domain
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_fromdomain(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_fromdomain(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_fromdomain(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushstring(l, "dkimf_xs_fromdomain");
	}
	else
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		lua_pushstring(l, (char *) dfc->mctx_domain);
	}

	return 1;
}

/*
**  DKIMF_XS_CLIENTHOST -- retrieve client hostname
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_clienthost(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_clienthost(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_clienthost(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushstring(l, "dkimf_xs_clienthost");
	}
	else
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);

		lua_pushstring(l, cc->cctx_host);
	}

	return 1;
}

/*
**  DKIMF_XS_CLIENTIP -- retrieve client IP address
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_clientip(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_clientip(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_clientip(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushstring(l, "dkimf_xs_clientip");
	}
	else
	{
		char ipbuf[BUFRSZ + 1];

		memset(ipbuf, '\0', sizeof ipbuf);

		cc = (struct connctx *) dkimf_getpriv(ctx);

#ifdef AF_INET6
		if (cc->cctx_ip.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *sa;

			sa = (struct sockaddr_in6 *) &cc->cctx_ip;

			if (inet_ntop(AF_INET6, &sa->sin6_addr,
			              ipbuf, sizeof ipbuf) == NULL)
			{
				lua_pushnil(l);
			}
			else
			{
				lua_pushstring(l, ipbuf);
			}
		}
		else
#endif /* AF_INET6 */
#ifdef AF_INET
		if (cc->cctx_ip.ss_family == AF_INET)
		{
			struct sockaddr_in *sa;

			sa = (struct sockaddr_in *) &cc->cctx_ip;

			if (inet_ntop(AF_INET, &sa->sin_addr,
			              ipbuf, sizeof ipbuf) == NULL)
			{
				lua_pushnil(l);
			}
			else
			{
				lua_pushstring(l, ipbuf);
			}
		}
		else
#endif /* AF_INET */
		{
			lua_pushnil(l);
		}
	}

	return 1;
}

#ifdef _FFR_REPUTATION
/*
**  DKIMF_XS_SPAM -- tag message as spam
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_spam(lua_State *l)
{
	SMFICTX *ctx;
	const char *keyname = NULL;
	const char *ident = NULL;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l, "odkim.spam(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "odkim.spam(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		dfc->mctx_spam = TRUE;
	}

	lua_pop(l, 1);

	return 0;
}
#endif /* _FFR_REPUTATION */

/*
**  DKIMF_XS_REQUESTSIG -- request a signature
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_requestsig(lua_State *l)
{
	int top;
	ssize_t signlen = (ssize_t) -1;
	SMFICTX *ctx;
	const char *keyname = NULL;
	const char *ident = NULL;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;

	assert(l != NULL);

	top = lua_gettop(l);

	if (top == 0 && top > 4)
	{
		lua_pushstring(l, "odkim.sign(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         (top > 1 && !lua_isstring(l, 2)) ||
	         (top > 2 && !lua_isstring(l, 3) && !lua_isnumber(l, 3)) ||
	         (top > 3 && !lua_isstring(l, 4) && !lua_isnumber(l, 4)))
	{
		lua_pushstring(l, "odkim.sign(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	if (ctx != NULL)
	{
		int c;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		conf = cc->cctx_config;

		for (c = 2; c <= top; c++)
		{
			if (c == 2)
			{
				keyname = lua_tostring(l, 2);
			}
			else if (lua_type(l, c) == LUA_TNUMBER)
			{
				if (signlen != (ssize_t) -1)
				{
					lua_pushstring(l,
					               "odkim.sign(): incorrect argument type");
					lua_error(l);
				}
				signlen = (ssize_t) lua_tonumber(l, c);
			}
			else
			{
				if (ident != NULL)
				{
					lua_pushstring(l,
					               "odkim.sign(): incorrect argument type");
					lua_error(l);
				}
				ident = lua_tostring(l, c);
			}
		}
	}

	lua_pop(l, top);

	if (ident != NULL && ident[0] == '\0')
		ident = NULL;

	if (ctx == NULL)
	{
		lua_pushnumber(l, 0);

		return 1;
	}

	if (conf->conf_keytabledb == NULL && keyname != NULL)
	{
		lua_pushstring(l, "odkim.sign(): request requires KeyTable");
		lua_error(l);
	}

	/* try to get the key */
	if (keyname != NULL)
	{
		switch (dkimf_add_signrequest(dfc, conf->conf_keytabledb,
		                              (char *) keyname,
		                              (char *) ident,
		                              signlen))
		{
		  case 3:
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "key '%s' could not be applied",
				       keyname);
			}
			lua_pushnumber(l, 0);
			return 1;

		  case 2:
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "key '%s' could not be loaded",
				       keyname);
			}
			lua_pushnumber(l, 0);
			return 1;

		  case 1:
			if (conf->conf_dolog)
				syslog(LOG_ERR, "key '%s' not found", keyname);
			lua_pushnumber(l, 0);
			return 1;

		  case -1:
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "error requesting key '%s'",
				       keyname);
			}
			lua_pushnumber(l, 0);
			return 1;
		}
	}
	else if (dkimf_add_signrequest(dfc, NULL, NULL, (char *) ident,
	                               (ssize_t) -1) != 0)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "failed to load/apply default key");

		lua_pushnumber(l, 0);

		return 1;
	}

	dfc->mctx_signalg = conf->conf_signalg;

	lua_pushnumber(l, 1);

	return 1;
}

/*
**  DKIMF_XS_REPLACEHEADER -- replace a header field's value
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_replaceheader(lua_State *l)
{
	int idx;
	const char *hdrname;
	const char *newval;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;
	Header hdr;

	assert(l != NULL);

	if (lua_gettop(l) != 4)
	{
		lua_pushstring(l,
		               "odkim.replace_header(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isnumber(l, 3) ||
	         !lua_isstring(l, 4))
	{
		lua_pushstring(l,
		               "odkim.replace_header(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	hdrname = lua_tostring(l, 2);
	idx = (int) lua_tonumber(l, 3);
	newval = lua_tostring(l, 4);

	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		conf = cc->cctx_config;
	}

	lua_pop(l, 3);

	if (ctx == NULL)
	{
		if (idx == 0)
			lua_pushstring(l, "dkimf_xs_replaceheader");
		else
			lua_pushnil(l);
		return 1;
	}

	hdr = dkimf_findheader(dfc, (char *) hdrname, idx);
	if (hdr == NULL)
	{
		lua_pushnil(l);
		return 1;
	}
	else
	{
		char *tmp;

		if (ctx != NULL && cc->cctx_noleadspc)
		{
			size_t len;

			len = strlen(newval);
			tmp = malloc(len + 2);
			if (tmp == NULL)
			{
				lua_pushnil(l);
				return 1;
			}

			tmp[0] = ' ';
			memcpy(&tmp[1], newval, len + 1);
		}
		else
		{
			tmp = strdup(newval);
			if (tmp == NULL)
			{
				lua_pushnil(l);
				return 1;
			}
		}

		free(hdr->hdr_val);
		hdr->hdr_val = tmp;

		return 0;
	}
}

/*
**  DKIMF_XS_GETENVFROM -- request envelope sender
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getenvfrom(lua_State *l)
{
	int idx;
	const char *hdrname;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;
	Header hdr;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_envfrom(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_envfrom(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);

	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
	}

	lua_pop(l, 1);

	if (ctx == NULL)
		lua_pushstring(l, "dkimf_xs_getenvfrom");
	else
		lua_pushstring(l, dfc->mctx_envfrom);
	return 1;
}

/*
**  DKIMF_XS_GETHEADER -- request a header value
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getheader(lua_State *l)
{
	int idx;
	const char *hdrname;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;
	Header hdr;

	assert(l != NULL);

	if (lua_gettop(l) != 3)
	{
		lua_pushstring(l,
		               "odkim.get_header(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) || !lua_isnumber(l, 3))
	{
		lua_pushstring(l,
		               "odkim.get_header(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	hdrname = lua_tostring(l, 2);
	idx = (int) lua_tonumber(l, 3);

	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		conf = cc->cctx_config;
	}

	lua_pop(l, 3);

	if (ctx == NULL)
	{
		if (idx == 0)
			lua_pushstring(l, "dkimf_xs_getheader");
		else
			lua_pushnil(l);
		return 1;
	}

	hdr = dkimf_findheader(dfc, (char *) hdrname, idx);
	if (hdr == NULL)
	{
		lua_pushnil(l);
		return 1;
	}
	else
	{
		lua_pushstring(l, hdr->hdr_val);
		return 1;
	}
}

/*
**  DKIMF_XS_POPAUTH -- see if the client's IP address is in the POPAUTH
**                      database
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_popauth(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.check_popauth(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.check_popauth(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 0);

		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);

#ifdef POPAUTH
	if (popdb == NULL)
	{
		lua_pushnil(l);
		return 1;
	}
	else
	{
		_Bool popauth;

		popauth = dkimf_checkpopauth(popdb, &cc->cctx_ip);

		lua_pushnumber(l, popauth ? 1 : 0);
		return 1;
	}
#else /* POPAUTH */
	lua_pushnil(l);
	return 1;
#endif /* POPAUTH */
}

/*
**  DKIMF_XS_INTERNALIP -- see if the client's IP address is "internal"
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_internalip(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct dkimf_config *conf;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.internal_ip(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.internal_ip(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);

		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	conf = cc->cctx_config;

	if (conf->conf_internal == NULL)
	{
		lua_pushnumber(l, 0);
	}
	else
	{
		_Bool internal;

		internal = dkimf_checkhost(conf->conf_internal, cc->cctx_host);
		internal = internal || dkimf_checkip(conf->conf_internal,
		                                     (struct sockaddr *) &cc->cctx_ip);

		lua_pushnumber(l, internal ? 1 : 0);
	}

	return 1;
}

/*
**  DKIMF_XS_DBOPEN -- open a DB handle
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_dbopen(lua_State *l)
{
	unsigned int flags = DKIMF_DB_FLAG_READONLY;
	int status;
	DKIMF_DB db;
	char *name;
	char *err = NULL;
	struct dkimf_lua_gc *gc;

	assert(l != NULL);

	if (lua_gettop(l) != 1 && lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.db_open(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_isstring(l, 1) ||
	         (lua_gettop(l) == 2 && !lua_isboolean(l, 2)))
	{
		lua_pushstring(l,
		               "odkim.db_open(): incorrect argument type");
		lua_error(l);
	}

	name = (char *)lua_tostring(l, 1);
	if (lua_gettop(l) == 2 && lua_toboolean(l, 2))
		flags |= DKIMF_DB_FLAG_ICASE;
	lua_pop(l, lua_gettop(l));

	status = dkimf_db_open(&db, name, flags, NULL, &err);

	if (status != 0)
	{
		if (err != NULL)
		{
			lua_pushfstring(l, "%s: odkim.db_open(): %s", name,
			                err);
		}
		else
		{
			lua_pushfstring(l, "%s: odkim.db_open() failed", name);
		}
		lua_error(l);
	}

	lua_getglobal(l, DKIMF_GC);
	gc = (struct dkimf_lua_gc *) lua_touserdata(l, 1);
	lua_pop(l, 1);
	dkimf_lua_gc_add(gc, db, DKIMF_LUA_GC_DB);

	lua_pushlightuserdata(l, db);

	return 1;
}

/*
**  DKIMF_XS_DBCLOSE -- close a DB handle
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_dbclose(lua_State *l)
{
	DKIMF_DB db;
	struct dkimf_lua_gc *gc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.db_close(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.db_close(): incorrect argument type");
		lua_error(l);
	}

	db = (DKIMF_DB) lua_touserdata(l, 1);

	lua_pop(l, 1);

	if (db == NULL)
	{
		lua_pushnumber(l, 0);
		return 1;
	}

	(void) dkimf_db_close(db);

	lua_getglobal(l, DKIMF_GC);
	gc = (struct dkimf_lua_gc *) lua_touserdata(l, 1);
	lua_pop(l, 1);
	dkimf_lua_gc_remove(gc, (void *) db);

	lua_pushnumber(l, 1);

	return 1;
}

/*
**  DKIMF_XS_DBHANDLE -- retrieve a DB handle
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_dbhandle(lua_State *l)
{
	int code;
	SMFICTX *ctx;
	struct connctx *cc;
	struct dkimf_config *conf;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.get_dbhandle(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) || !lua_isnumber(l, 2))
	{
		lua_pushstring(l,
		               "odkim.get_dbhandle(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);

	if (ctx == NULL)
	{
		lua_pop(l, 2);
		lua_pushnil(l);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	conf = cc->cctx_config;

	code = (int) lua_tonumber(l, 1);
	lua_pop(l, 2);

	switch (code)
	{
	  case DB_DOMAINS:
		if (conf->conf_domainsdb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_domainsdb);
		break;

	  case DB_THIRDPARTY:
		if (conf->conf_thirdpartydb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_thirdpartydb);
		break;

	  case DB_DONTSIGNTO:
		if (conf->conf_dontsigntodb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_dontsigntodb);
		break;

	  case DB_MTAS:
		if (conf->conf_mtasdb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_mtasdb);
		break;

	  case DB_MACROS:
		if (conf->conf_macrosdb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_macrosdb);
		break;

	  case DB_SIGNINGTABLE:
		if (conf->conf_signtabledb == NULL)
			lua_pushnil(l);
		else
			lua_pushlightuserdata(l, conf->conf_signtabledb);
		break;

	  default:
		lua_pushnil(l);
		break;
	}

	return 1;
}

/*
**  DKIMF_XS_RCPTCOUNT -- retrieve recipient count
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_rcptcount(lua_State *l)
{
	int rcnt;
	SMFICTX *ctx;
	struct connctx *cc;
	struct dkimf_config *conf;
	struct msgctx *dfc;
	struct addrlist *addr;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.rcpt_count(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.rcpt_count(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	conf = cc->cctx_config;
	dfc = cc->cctx_msg;

	rcnt = 0;
	
	for (addr = dfc->mctx_rcptlist; addr != NULL; addr = addr->a_next)
		rcnt++;

	lua_pushnumber(l, rcnt);

	return 1;
}

/*
**  DKIMF_XS_RCPT -- retrieve an envelope recipient
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_rcpt(lua_State *l)
{
	int rcnt;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct addrlist *addr;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.get_rcpt(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) || !lua_isnumber(l, 2))
	{
		lua_pushstring(l,
		               "odkim.get_rcpt(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	rcnt = (int) lua_tonumber(l, 1);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushstring(l, "dkimf_xs_rcpt");
		return 1;
	}
	
	cc = (struct connctx *) dkimf_getpriv(ctx);
	dfc = cc->cctx_msg;

	addr = dfc->mctx_rcptlist;
	while (rcnt > 0 && addr != NULL)
	{
		addr = addr->a_next;
		rcnt--;
	}

	if (addr == NULL)
		lua_pushnil(l);
	else
		lua_pushstring(l, addr->a_addr);

	return 1;
}

/*
**  DKIMF_XS_RCPTARRAY -- retrieve all recipients into a Lua array
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_rcptarray(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_rcptarray(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_rcptarray(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	lua_newtable(l);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
		lua_pushstring(l, "dkimf_xs_rcptarray");
		lua_settable(l, -3);
	}
	else
	{
		int idx;
		struct addrlist *addr;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		for (addr = dfc->mctx_rcptlist, idx = 1;
		     addr != NULL;
		     addr = addr->a_next, idx++)
		{
			lua_pushnumber(l, idx);
			lua_pushstring(l, addr->a_addr);
			lua_settable(l, -3);
		}
	}

	return 1;
}

/*
**  DKIMF_XS_DBQUERY -- check for a record in a database
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_dbquery(lua_State *l)
{
	int status;
	_Bool exists;
	DKIMF_DB db;
	const char *str;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.db_check(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l,
		               "odkim.db_check(): incorrect argument type");
		lua_error(l);
	}

	db = (DKIMF_DB) lua_touserdata(l, 1);
	str = lua_tostring(l, 2);
	lua_pop(l, 2);

	if (db == NULL || str == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	exists = FALSE;
	status = dkimf_db_get(db, (char *) str, 0, NULL, 0, &exists);
	if (status == 0)
		lua_pushnumber(l, exists ? 1 : 0);
	else
		lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_SETPARTIAL -- request l= tags
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_setpartial(lua_State *l)
{
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.use_ltag(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.use_ltag(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx != NULL)
	{
		struct connctx *cc;
		struct msgctx *dfc;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		dfc->mctx_ltag = TRUE;
	}

	lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_VERIFY -- set up verification
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_verify(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.verify(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.verify(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;
		conf = cc->cctx_config;

		if (dfc->mctx_dkimv == NULL)
		{
			DKIM_STAT status;

			dfc->mctx_dkimv = dkim_verify(conf->conf_libopendkim,
			                              dfc->mctx_jobid, NULL,
			                              &status);

			if (dfc->mctx_dkimv == NULL)
			{
				lua_pushstring(l, dkim_getresultstr(status));
				return 1;
			}
		}
	}

	lua_pushnil(l);
	return 1;
}

/*
**  DKIMF_XS_GETSIGARRAY -- get signature handle array
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsigarray(lua_State *l)
{
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_sigarray(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_sigarray(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx != NULL)
	{
		struct connctx *cc;
		struct msgctx *dfc;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		if (dfc->mctx_dkimv == NULL)
		{
			lua_pushnumber(l, 0);
		}
		else
		{
			int nsigs;
			DKIM_STAT status;
			DKIM_SIGINFO **sigs;

			status = dkim_getsiglist(dfc->mctx_dkimv,
			                         &sigs, &nsigs);
			if (status != DKIM_STAT_OK)
			{
				lua_pushnil(l);
			}
			else
			{
				int c;

				lua_newtable(l);

				for (c = 0; c < nsigs; c++)
				{
					lua_pushnumber(l, c + 1);
					lua_pushlightuserdata(l, sigs[c]);
					lua_settable(l, -3);
				}
			}
		}
	}
	else
	{
		lua_pushnil(l);
	}
	
	return 1;
}

/*
**  DKIMF_XS_GETSIGCOUNT -- get signature count
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsigcount(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.get_sigcount(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.get_sigcount(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx != NULL)
	{
		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		if (dfc->mctx_dkimv == NULL)
		{
			lua_pushnumber(l, 0);
		}
		else
		{
			DKIM_STAT status;
			int nsigs;
			DKIM_SIGINFO **sigs;

			status = dkim_getsiglist(dfc->mctx_dkimv,
			                         &sigs, &nsigs);
			if (status != DKIM_STAT_OK)
				lua_pushnil(l);
			else
				lua_pushnumber(l, nsigs);
		}
	}
	else
	{
		lua_pushnumber(l, 1);
	}
	
	return 1;
}

/*
**  DKIMF_XS_GETSIGHANDLE -- get signature handle
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsighandle(lua_State *l)
{
	int idx;
	int nsigs;
	DKIM_STAT status;
	SMFICTX *ctx;
	DKIM_SIGINFO **sigs;
	struct connctx *cc;
	struct msgctx *dfc;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.get_sighandle(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isnumber(l, 2))
	{
		lua_pushstring(l,
		               "odkim.get_sighandle(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	idx = (int) lua_tonumber(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushlightuserdata(l, NULL);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	dfc = cc->cctx_msg;

	if (dfc->mctx_dkimv == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	status = dkim_getsiglist(dfc->mctx_dkimv, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
	{
		lua_pushnil(l);
		return 1;
	}

	if (idx < 0 || idx >= nsigs)
	{
		lua_pushstring(l, "odkim.get_sighandle(): invalid request");
		lua_error(l);
	}

	lua_pushlightuserdata(l, sigs[idx]);

	return 1;
}

/*
**  DKIMF_XS_GETSIGDOMAIN -- get signature's signing domain ("d=")
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsigdomain(lua_State *l)
{
	DKIM_SIGINFO *sig;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.sig_getdomain(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.sig_getdomain(): incorrect argument type");
		lua_error(l);
	}

	sig = (DKIM_SIGINFO *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (sig == NULL)
		lua_pushlightuserdata(l, NULL);
	else
		lua_pushstring(l, (char *) dkim_sig_getdomain(sig));

	return 1;
}

/*
**  DKIMF_XS_SIGIGNORE -- ignore a signature and its result
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_sigignore(lua_State *l)
{
	DKIM_SIGINFO *sig;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.sig_getdomain(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.sig_getdomain(): incorrect argument type");
		lua_error(l);
	}

	sig = (DKIM_SIGINFO *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (sig != NULL)
		dkim_sig_ignore(sig);

	lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_GETSIGIDENTITY -- get signature's signing identity ("i=")
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsigidentity(lua_State *l)
{
	DKIM_STAT status;
	DKIM_SIGINFO *sig;
	u_char addr[MAXADDRESS + 1];

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.sig_getidentity(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.sig_getidentity(): incorrect argument type");
		lua_error(l);
	}

	sig = (DKIM_SIGINFO *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (sig == NULL)
	{
		lua_pushstring(l, "dkimf_xs_getsigidentity");
		return 1;
	}

	memset(addr, '\0', sizeof addr);
	status = dkim_sig_getidentity(NULL, sig, addr, sizeof addr - 1);
	if (status != DKIM_STAT_OK)
		lua_pushnil(l);
	else
		lua_pushstring(l, (char *) addr);

	return 1;
}

/*
**  DKIMF_XS_GETSYMVAL -- get MTA symbol
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_getsymval(lua_State *l)
{
	char *name;
	char *sym;
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.get_mtasymbol(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l,
		               "odkim.get_mtasymbol(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushstring(l, "dkimf_xs_getmtasymbol");
	}
	else
	{
		sym = dkimf_getsymval(ctx, name);
		if (sym == NULL)
			lua_pushnil(l);
		else
			lua_pushstring(l, sym);
	}

	return 1;
}

/*
**  DKIMF_XS_SIGRESULT -- get signature's result code
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_sigresult(lua_State *l)
{
	DKIM_SIGINFO *sig;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.sig_result(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.sig_result(): incorrect argument type");
		lua_error(l);
	}

	sig = (DKIM_SIGINFO *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (sig == NULL)
		lua_pushnumber(l, 0);
	else
		lua_pushnumber(l, dkim_sig_geterror(sig));

	return 1;
}

/*
**  DKIMF_XS_SIGBHRESULT -- get signature's body hash result code
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_sigbhresult(lua_State *l)
{
	DKIM_SIGINFO *sig;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l,
		               "odkim.sig_bhresult(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l,
		               "odkim.sig_bhresult(): incorrect argument type");
		lua_error(l);
	}

	sig = (DKIM_SIGINFO *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (sig == NULL)
		lua_pushnumber(l, 0);
	else
		lua_pushnumber(l, dkim_sig_getbh(sig));

	return 1;
}

/*
**  DKIMF_XS_BODYLENGTH -- return total body length
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_bodylength(lua_State *l)
{
	ssize_t body;
	DKIM_STAT status;
	SMFICTX *ctx;
	DKIM_SIGINFO *sig;
	struct connctx *cc;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.sig_bodylength(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_islightuserdata(l, 2))
	{
		lua_pushstring(l,
		               "odkim.sig_bodylength(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	sig = (DKIM_SIGINFO *) lua_touserdata(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 100);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	if (cc->cctx_msg == NULL || cc->cctx_msg->mctx_dkimv == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	status = dkim_sig_getcanonlen(cc->cctx_msg->mctx_dkimv, sig, &body,
	                              NULL, NULL);
	if (status != DKIM_STAT_OK)
		lua_pushnil(l);
	else
		lua_pushnumber(l, body);

	return 1;
}

/*
**  DKIMF_XS_CANONLENGTH -- return length canonicalized by a signature
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_canonlength(lua_State *l)
{
	ssize_t cl;
	DKIM_STAT status;
	SMFICTX *ctx;
	DKIM_SIGINFO *sig;
	struct connctx *cc;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.sig_canonlength(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_islightuserdata(l, 2))
	{
		lua_pushstring(l,
		               "odkim.sig_canonlength(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	sig = (DKIM_SIGINFO *) lua_touserdata(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 100);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	if (cc->cctx_msg == NULL || cc->cctx_msg->mctx_dkimv == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	status = dkim_sig_getcanonlen(cc->cctx_msg->mctx_dkimv, sig, NULL,
	                              &cl, NULL);
	if (status != DKIM_STAT_OK)
		lua_pushnil(l);
	else
		lua_pushnumber(l, cl);

	return 1;
}

/*
**  DKIMF_XS_ADDHEADER -- add a header field
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_addheader(lua_State *l)
{
	char *name;
	char *value;
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 3)
	{
		lua_pushstring(l,
		               "odkim.add_header(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isstring(l, 3))
	{
		lua_pushstring(l,
		               "odkim.add_header(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	value = (char *) lua_tostring(l, 3);
	lua_pop(l, 3);

	if (ctx == NULL)
		lua_pushnil(l);
	else if (dkimf_insheader(ctx, 1, name, value) == MI_SUCCESS)
		lua_pushnumber(l, 1);
	else
		lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_DELHEADER -- delete a header field
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_delheader(lua_State *l)
{
	int idx;
	char *name;
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 3)
	{
		lua_pushstring(l,
		               "odkim.del_header(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isnumber(l, 3))
	{
		lua_pushstring(l,
		               "odkim.del_header(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	idx = lua_tonumber(l, 3);
	lua_pop(l, 3);

	if (ctx == NULL)
		lua_pushnil(l);
	else if (dkimf_chgheader(ctx, name, 1, NULL) == MI_SUCCESS)
		lua_pushnumber(l, 1);
	else
		lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_ADDRCPT -- add a recipient
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_addrcpt(lua_State *l)
{
	char *addr;
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.add_rcpt(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l, "odkim.add_rcpt(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	addr = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
		lua_pushnumber(l, 1);
	else if (dkimf_addrcpt(ctx, addr) == MI_SUCCESS)
		lua_pushnumber(l, 1);
	else
		lua_pushnil(l);

	return 1;
}

/*
**  DKIMF_XS_DELRCPT -- delete a recipient
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_delrcpt(lua_State *l)
{
	char *addr;
	struct addrlist *a;
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;
	struct dkimf_config *conf;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.delete_rcpt(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l,
		               "odkim.delete_rcpt(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	addr = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	conf = cc->cctx_config;
	dfc = cc->cctx_msg;

	/* see if this is a known recipient */
	for (a = dfc->mctx_rcptlist; a != NULL; a = a->a_next)
	{
		if (strcasecmp(a->a_addr, addr) == 0)
			break;
	}

	/* if not found, report error */
	if (a == NULL)
	{
		lua_pushnil(l);
		return 1;
	}

	/* delete and replace with a header field */
	if (dkimf_delrcpt(ctx, a->a_addr) != MI_SUCCESS)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: smfi_delrcpt() failed",
			       dfc->mctx_jobid);
		}
	}
	else
	{
		char header[MAXADDRESS + 8];

		snprintf(header, sizeof header, "rfc822;%s", a->a_addr);
		if (dkimf_addheader(ctx, ORCPTHEADER, header) != MI_SUCCESS)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: smfi_addheader() failed",
				       dfc->mctx_jobid);
			}
		}
	}

	lua_pushnumber(l, 1);

	return 1;
}

/*
**  DKIMF_XS_RESIGN -- set up for re-signing
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_resign(lua_State *l)
{
	SMFICTX *ctx;
	struct connctx *cc;
	struct msgctx *dfc;

	assert(l != NULL);

	if (lua_gettop(l) != 1)
	{
		lua_pushstring(l, "odkim.resign(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "odkim.resign(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
		return 1;
	}

	cc = (struct connctx *) dkimf_getpriv(ctx);
	dfc = cc->cctx_msg;

# ifdef _FFR_RESIGN
	dfc->mctx_resign = TRUE;

	lua_pushnumber(l, 1);
# else /* _FFR_RESIGN */
	lua_pushnil(l);
# endif /* _FFR_RESIGN */

	return 1;
}

/*
**  DKIMF_XS_SETREPLY -- set SMTP reply text
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_setreply(lua_State *l)
{
	SMFICTX *ctx;
	char *rcode = NULL;
	char *xcode = NULL;
	char *message = NULL;

	assert(l != NULL);

	if (lua_gettop(l) != 4)
	{
		lua_pushstring(l,
		               "odkim.set_reply(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isstring(l, 3) ||
	         !lua_isstring(l, 4))
	{
		lua_pushstring(l,
		               "odkim.set_reply(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	rcode = (char *) lua_tostring(l, 2);
	xcode = (char *) lua_tostring(l, 3);
	message = (char *) lua_tostring(l, 4);
	lua_pop(l, 4);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
		return 1;
	}

	if (strlen(xcode) == 0)
		xcode = NULL;

	if (dkimf_setreply(ctx, rcode, xcode, message) == MI_FAILURE)
		lua_pushnil(l);
	else
		lua_pushnumber(l, 1);

	return 1;
}

/*
**  DKIMF_XS_QUARANTINE -- request quarantine
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_quarantine(lua_State *l)
{
	SMFICTX *ctx;
	char *message = NULL;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.quarantine(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2))
	{
		lua_pushstring(l,
		               "odkim.quarantine(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	message = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
		lua_pushnumber(l, 1);
	else if (dkimf_quarantine(ctx, message) == MI_FAILURE)
		lua_pushnil(l);
	else
		lua_pushnumber(l, 1);

	return 1;
}

/*
**  DKIMF_XS_SETRESULT -- set milter result
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_setresult(lua_State *l)
{
	SMFICTX *ctx;
	int mresult;

	assert(l != NULL);

	if (lua_gettop(l) != 2)
	{
		lua_pushstring(l,
		               "odkim.set_result(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isnumber(l, 2))
	{
		lua_pushstring(l,
		               "odkim.set_result(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	mresult = (int) lua_tonumber(l, 2);
	lua_pop(l, 2);

	if (ctx == NULL)
	{
		lua_pushnumber(l, 1);
	}
	else if (mresult == SMFIS_TEMPFAIL ||
	         mresult == SMFIS_ACCEPT ||
	         mresult == SMFIS_DISCARD ||
	         mresult == SMFIS_REJECT)
	{
		struct msgctx *dfc;
		struct connctx *cc;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		dfc->mctx_mresult = mresult;
		lua_pushnumber(l, 1);
	}
	else
	{
		lua_pushnil(l);
	}

	return 1;
}

# ifdef _FFR_STATSEXT
/*
**  DKIMF_XS_STATSEXT -- record extended statistics
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**  	Number of stack items pushed.
*/

int
dkimf_xs_statsext(lua_State *l)
{
	char *name;
	char *value;
	SMFICTX *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 3)
	{
		lua_pushstring(l,
		               "odkim.stats(): incorrect argument count");
		lua_error(l);
	}
	else if (!lua_islightuserdata(l, 1) ||
	         !lua_isstring(l, 2) ||
	         !lua_isstring(l, 3))
	{
		lua_pushstring(l,
		               "odkim.stats(): incorrect argument type");
		lua_error(l);
	}

	ctx = (SMFICTX *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	value = (char *) lua_tostring(l, 3);
	lua_pop(l, 3);

	if (ctx != NULL)
	{
		struct statsext *se;
		struct connctx *cc;
		struct msgctx *dfc;

		cc = (struct connctx *) dkimf_getpriv(ctx);
		dfc = cc->cctx_msg;

		se = (struct statsext *) malloc(sizeof(struct statsext));
		if (se == NULL)
		{
			lua_pushfstring(l, "odkim.stats(): malloc(): %s",
			                strerror(errno));
			lua_error(l);
		}

		se->se_next = dfc->mctx_statsext;
		dfc->mctx_statsext = se;

		strlcpy(se->se_name, name, sizeof se->se_name);
		strlcpy(se->se_value, value, sizeof se->se_value);
	}

	lua_pushnil(l);

	return 1;
}
# endif /* _FFR_STATSEXT */
#endif /* USE_LUA */

#ifdef _FFR_VBR
/*
**  DKIMF_VALID_VBR -- determine whether or not VBR should be verified
**
**  Parameters:
**  	dfc -- filter context
**
**  Return value:
**  	TRUE iff the message should have its VBR data checked
*/

static _Bool
dkimf_valid_vbr(struct msgctx *dfc)
{
	_Bool ret;
	int c = 0;
	char *p;
	char *q;
	char *last = NULL;
	Header hdr;
	char mc[DKIM_MAXHEADER + 1];
	char tmp[DKIM_MAXHEADER + 1];

	assert(dfc != NULL);

	memset(mc, '\0', sizeof mc);

	for (c = 0; c == 0 || ret; c++)
	{
		hdr = dkimf_findheader(dfc, VBR_INFOHEADER, c);

		if (hdr == NULL)
			break;

		if (c == 0)
			ret = TRUE;

		strlcpy(tmp, hdr->hdr_val, sizeof tmp);

		for (p = strtok_r(tmp, ";", &last);
		     p != NULL;
		     p = strtok_r(NULL, ";", &last))
		{
			q = strchr(p, '=');
			if (q == NULL)
				continue;
			*q = '\0';

			dkimf_trimspaces(p);
			dkimf_trimspaces(q + 1);

			if (strcasecmp(p, "mc") == 0)
			{
				if (mc[0] == '\0')
					strlcpy(mc, q + 1, sizeof mc);
				else if (strcasecmp(q + 1, mc) != 0)
					ret = FALSE;

				break;
			}
		}
	}

	if (mc[0] == '\0')
		ret = FALSE;

	return ret;
}
#endif /* _FFR_VBR */

/*
**  DKIMF_ADD_AR_FIELDS -- add Authentication-Results header fields
**
**  Parameters:
**  	dfc -- filter context
**  	conf -- configuration handle
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
dkimf_add_ar_fields(struct msgctx *dfc, struct dkimf_config *conf,
                    SMFICTX *ctx)
{
	assert(dfc != NULL);
	assert(conf != NULL);
	assert(ctx != NULL);

	if (dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
	                    (char *) dfc->mctx_dkimar) == MI_FAILURE)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: %s header add failed",
			       dfc->mctx_jobid, AUTHRESULTSHDR);
		}
	}
}

/*
**  DKIMF_DB_ERROR -- syslog errors related to db retrieval
**
**  Parameters:
**  	db -- the db
**      key -- what was looked up
**
**  Return value:
**  	None.
*/

static void
dkimf_db_error(DKIMF_DB db, const char *key)
{
	char errbuf[BUFRSZ];

	assert(db != NULL);
	assert(key != NULL);

	(void) dkimf_db_strerror(db, errbuf, sizeof errbuf);

	syslog(LOG_ERR, "error looking up \"%s\" in database: %s",
	       key, errbuf);
}


/*
**  DKIMF_INIT_SYSLOG -- initialize syslog()
**
**  Parameters:
**  	facility -- name of the syslog facility to use when logging;
**  	            can be NULL to request the default
**
**  Return value:
**  	None.
*/

static void
dkimf_init_syslog(char *facility)
{
#ifdef LOG_MAIL
	int code;
	struct lookup *p = NULL;

	closelog();

	code = LOG_MAIL;
	if (facility != NULL)
	{
		for (p = log_facilities; p != NULL; p++)
		{
			if (strcasecmp(p->str, facility) == 0)
			{
				code = p->code;
				break;
			}
		}
	}

	openlog(progname, LOG_PID, code);
#else /* LOG_MAIL */
	closelog();

	openlog(progname, LOG_PID);
#endif /* LOG_MAIL */
}

/*
**  DKIMF_RESTART_CHECK -- initialize/check restart rate information
**
**  Parameters:
**  	n -- size of restart rate array to initialize/enforce
**  	t -- maximum time range for restarts (0 == init)
**
**  Return value:
**  	TRUE -- OK to continue
**  	FALSE -- error
*/

static _Bool
dkimf_restart_check(int n, time_t t)
{
	static int idx;				/* last filled slot */
	static int alen;			/* allocated length */
	static time_t *list;

	if (t == 0)
	{
		alen = n * sizeof(time_t);

		list = (time_t *) malloc(alen);

		if (list == NULL)
			return FALSE;

		memset(list, '\0', alen);

		idx = 0;
		alen = n;

		return TRUE;
	}
	else
	{
		int which;

		time_t now;

		(void) time(&now);

		which = (idx - 1) % alen;
		if (which == -1)
			which = alen - 1;

		if (list[which] != 0 &&
		    list[which] + t > now)
			return FALSE;

		list[which] = now;
		idx++;

		return TRUE;
	}
}

/*
**  DKIMF_REPTOKEN -- replace a token in an input string with another string
**
**  Parameters:
**  	out -- output buffer
**  	outlen -- output buffer length
**  	in -- input string
**  	sub -- substitution string
**
**  Return value:
**  	Bytes of output; may be larger than "outlen" if "out" was too small.
*/

size_t
dkimf_reptoken(u_char *out, size_t outlen, u_char *in, u_char *sub)
{
	size_t ret = 0;
	u_char *p;
	u_char *q;
	u_char *end;

	assert(out != NULL);
	assert(in != NULL);
	assert(sub != NULL);

	memset(out, '\0', outlen);

	q = out;
	end = q + outlen - 1;

	for (p = in; *p != '\0'; p++)
	{
		if (*p == '%')
		{
			size_t c;

			c = strlcpy((char *) q, (char *) sub, outlen - ret);
			q += c;
			ret += c;
		}
		else
		{
			if (q < end)
			{
				*q = *p;
				q++;
				ret++;
			}
		}
	}

	return ret;
}

/*
**  DKIMF_CHECKFSNODE -- check a filesystem node for safety
**
**  Parameters:
**  	path -- path of the node to check
**  	myuid -- executing user's effective uid
**  	myname -- executing user's login
**  	ino -- evaluated inode (returned)
**  	err -- error buffer
**  	errlen -- error buffer length
**
**  Return value:
**  	1 -- node is safe to use
**  	0 -- node is not safe to use
**  	-1 -- error (check errno)
**
**  Notes:
**  	"Safe" here means the target file cannot be read or written by anyone
**  	other than the executing user and the superuser.  The entire directory
**  	tree is checked from the root down after resolution of symlinks and
**  	references to "." and ".." looking for errant "write" bits on
**   	directories and the file itself.
**
**  	To prevent attacks through symbolic links, this function also returns
**  	the inode of the object it evaluated if that object was a file.  Thus,
**  	if the caller first opens the file but doesn't read from it, then the
**  	returned inode can be compared to the inode of the opened descriptor
**  	to ensure that what was opened was safe at the time open() was called.
**  	An inode of -1 is reported if some directory above the target was
**  	sufficiently locked down that the inode comparison isn't necessary.
**
**  	This still isn't bulletproof; there's a race between the time of the
**  	open() call and the result returned by this function.  I'm not sure if
**	that can be improved.
*/

static int
dkimf_checkfsnode(const char *path, uid_t myuid, char *myname, ino_t *ino,
                  char *err, size_t errlen)
{
	int status;
	struct passwd *pw;
	struct group *gr;
	struct stat s;

	assert(path != NULL);
	assert(myname != NULL);
	assert(ino != NULL);

	status = stat(path, &s);
	if (status != 0)
		return -1;

	if (S_ISREG(s.st_mode))
	{

		/* owned by root or by me */
		if (s.st_uid != 0 && s.st_uid != myuid)
		{
			if (err != NULL)
			{
				snprintf(err, errlen,
				         "%s is not owned by the executing uid (%d)%s",
				         path, myuid,
				         myuid != 0 ? " or the superuser"
				                    : "");
			}
			return 0;
		}

		/* if group read/write, the group is only me and/or root */
		if ((s.st_mode & (S_IRGRP|S_IWGRP)) != 0)
		{
			int c;

			/* check if anyone else has this file's gid */
			pthread_mutex_lock(&pwdb_lock);
			setpwent();
			for (pw = getpwent(); pw != NULL; pw = getpwent())
			{
				if (pw->pw_uid != myuid &&
				    pw->pw_uid != 0 &&
				    s.st_gid == pw->pw_gid)
				{
					if (err != NULL)
					{
						snprintf(err, errlen,
						         "%s is in group %u which has multiple users (e.g. \"%s\")",
						         path, s.st_gid,
						         pw->pw_name);
					}
					pthread_mutex_unlock(&pwdb_lock);
					return 0;
				}
			}
			endpwent();

			/* check if this group contains anyone else */
			gr = getgrgid(s.st_gid);
			if (gr == NULL)
			{
				pthread_mutex_unlock(&pwdb_lock);
				return -1;
			}

			for (c = 0; gr->gr_mem[c] != NULL; c++)
			{
				if (strcmp(gr->gr_mem[c], myname) != 0 &&
				    strcmp(gr->gr_mem[c], SUPERUSER) != 0)
				{
					if (err != NULL)
					{
						snprintf(err, errlen,
						         "%s is in group %u which has multiple users (e.g., \"%s\")",
						         path, s.st_gid,
						         gr->gr_mem[c]);
					}
					pthread_mutex_unlock(&pwdb_lock);
					return 0;
				}
			}

			pthread_mutex_unlock(&pwdb_lock);
		}

		/* not read/write by others */
		if ((s.st_mode & (S_IROTH|S_IWOTH)) != 0)
		{
			if (err != NULL)
			{
				snprintf(err, errlen,
				         "%s can be read or written by other users",
				         path);
			}

			return 0;
		}

		*ino = s.st_ino;
	}
	else if (S_ISDIR(s.st_mode))
	{
		/* other write needs to be off */
		if ((s.st_mode & S_IWOTH) != 0)
		{
			if (err != NULL)
			{
				snprintf(err, errlen,
				         "%s can be read or written by other users",
				         path);
			}
			return 0;
		}

		/* group write needs to be super-user or me only */
		if ((s.st_mode & S_IWGRP) != 0)
		{
			int c;

			/* check if anyone else has this file's gid */
			pthread_mutex_lock(&pwdb_lock);
			setpwent();
			for (pw = getpwent(); pw != NULL; pw = getpwent())
			{
				if (pw->pw_uid != myuid &&
				    pw->pw_uid != 0 &&
				    s.st_gid == pw->pw_gid)
				{
					if (err != NULL)
					{
						snprintf(err, errlen,
						         "%s is in group %u which has multiple users (e.g., \"%s\")",
						         myname, s.st_gid,
						         pw->pw_name);
					}

					pthread_mutex_unlock(&pwdb_lock);
					return 0;
				}
			}

			/* check if this group contains anyone else */
			gr = getgrgid(s.st_gid);
			if (gr == NULL)
			{
				pthread_mutex_unlock(&pwdb_lock);
				return -1;
			}

			for (c = 0; gr->gr_mem[c] != NULL; c++)
			{
				if (strcmp(gr->gr_mem[c], myname) != 0 &&
				    strcmp(gr->gr_mem[c], SUPERUSER) != 0)
				{
					if (err != NULL)
					{
						snprintf(err, errlen,
						         "%s is in group %u which has multiple users (e.g., \"%s\")",
						         myname, s.st_gid,
						         gr->gr_mem[c]);
					}

					pthread_mutex_unlock(&pwdb_lock);
					return 0;
				}
			}

			pthread_mutex_unlock(&pwdb_lock);
		}

		/* owner write needs to be super-user or me only */
		if ((s.st_mode & S_IWUSR) != 0 &&
		    (s.st_uid != 0 && s.st_uid != myuid))
		{
			if (err != NULL)
			{
				snprintf(err, errlen,
				         "%s is writeable and owned by uid %u which is not the executing uid (%u)%s",
				         path, s.st_uid, myuid,
				         myuid != 0 ? " or the superuser"
				                    : "");
			}

			return 0;
		}

		/* if nobody else can execute below here, that's good enough */
		if ((s.st_mode & (S_IXGRP|S_IXOTH)) == 0)
		{
			*ino = (ino_t) -1;
			return 1;
		}
	}

	return 1;
}

/*
**  DKIMF_SECUREFILE -- determine whether a file at a specific path is "safe"
**
**  Parameters:
**  	path -- path to evaluate
**  	ino -- inode of evaluated object
** 	myuid -- user to impersonate (-1 means "me")
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	As for dkimf_checkfsnode().
**
**  Notes:
**  	If realpath() is available, this function checks the entire resolved
**  	filesystem tree from the root to the target file to ensure there are no
**  	permissions that would allow someone else on the system to either read
**  	or replace the file being evaluated.  (It's designed to check private
**  	key files.)  Without realpath(), only the target filename is checked.
*/

int
dkimf_securefile(const char *path, ino_t *ino, uid_t myuid, char *err,
                 size_t errlen)
{
	int status;
	struct passwd *pw;
#ifdef HAVE_REALPATH
	char *p;
	char *q;
	char real[MAXPATHLEN + 1];
	char partial[MAXPATHLEN + 1];
	char myname[BUFRSZ + 1];
#endif /* HAVE_REALPATH */

	assert(path != NULL);
	assert(ino != NULL);

	/* figure out who I am */
	pthread_mutex_lock(&pwdb_lock);

	if (myuid == (uid_t) -1)
		pw = getpwuid(geteuid());
	else
		pw = getpwuid(myuid);

	if (pw == NULL)
	{
		pthread_mutex_unlock(&pwdb_lock);
		return -1;
	}

	if (myuid == (uid_t) -1)
		myuid = pw->pw_uid;

	pthread_mutex_unlock(&pwdb_lock);

#ifdef HAVE_REALPATH
	strlcpy(myname, pw->pw_name, sizeof myname);

	p = realpath(path, real);
	if (p == NULL)
		return -1;

	/*
	**  Check each node in the tree to ensure that:
	**  1) The file itself is read-write only by the executing user and the
	**  	super-user;
	**  2) No directory above the file is writeable by anyone other than
	**  	the executing user and the super-user.
	*/

	partial[0] = '/';
	partial[1] = '\0';

# ifdef HAVE_STRSEP
	q = real;
	while ((p = strsep(&q, "/")) != NULL)
# else /* HAVE_STRSEP */
	q = NULL;
	for (p = strtok_r(real, "/", &q);
	     p != NULL;
	     p = strtok_r(NULL, "/", &q))
# endif /* HAVE_STRSEP */
	{
		strlcat(partial, p, sizeof partial);
		status = dkimf_checkfsnode((const char *) partial,
		                           myuid, myname, ino, err, errlen);
		if (status != 1)
			return status;

		if (partial[1] != '\0')
			strlcat(partial, "/", sizeof partial); 
	}

	return 1;
#else /* HAVE_REALPATH */
	struct stat s;

	status = stat(path, &s);
	if (status != 0)
		return -1;

	/* we don't own it and neither does the super-user; bad */
	if (s.st_uid != myuid && s.st_uid != 0)
		return 0;

	/* world readable/writeable; bad */
	if ((s.st_node & (S_IROTH|S_IWOTH)) != 0)
		return 0;

	/* group read/write is bad if others are in that group */
	if ((s.st_mode & (S_IRGRP|S_IWGRP)) != 0)
	{
		int c;
		struct group *gr;

		/* get the file's group entry */
		pthread_mutex_lock(&pwdb_lock);
		gr = getgrgid(s.st_gid);
		if (gr == NULL)
		{
			pthread_mutex_unlock(&pwdb_lock);
			return -1;
		}

		for (c = 0; gr->gr_mem[c] != NULL; c++)
		{
			if (strcmp(gr->gr_mem[c], pw->pw_name) != 0)
			{
				pthread_mutex_unlock(&pwdb_lock);
				return 0;
			}
		}

		setpwent();
		while (pw = getpwent(); pw != NULL; pw = getpwent())
		{
			if (pw->pw_uid != myuid && pw->pw_gid == s.st_gid)
			{
				pthread_mutex_unlock(&pwdb_lock);
				return 0;
			}
		}
		endpwent();

		pthread_mutex_unlock(&pwdb_lock);
	}
		
	/* guess we're okay... */
	*ino = s.st_ino;
	return 1;
#endif /* HAVE_REALPATH */
}

/*
**  DKIMF_LOADKEY -- resolve a key
**
**  Parameters:
**  	buf -- key buffer
**  	buflen -- pointer to key buffer's length (updated)
**  	insecure -- key is insecure (returned)
**  	error -- buffer to receive error string
**  	errlen -- bytes available at "error"
**
**  Return value:
**  	TRUE on successful load, false otherwise.
**
**  Notes:
**  	The caller might pass a key or a filename in "buf".  If we think it's a
**  	filename, replace the contents of "buf" with what we find in that file.
*/

static _Bool
dkimf_loadkey(char *buf, size_t *buflen, _Bool *insecure, char *error,
              size_t errlen)
{
	ino_t ino;

	assert(buf != NULL);
	assert(buflen != NULL);

	if (buf[0] == '/' || (buf[0] == '.' && buf[1] == '/') ||
	    (buf[0] == '.' && buf[1] == '.' && buf[2] == '/'))
	{
		int fd;
		int status;
		ssize_t rlen;
		struct stat s;

		fd = open(buf, O_RDONLY);
		if (fd < 0)
		{
			if (error != NULL)
				strlcpy(error, strerror(errno), errlen);
			return FALSE;
		}

		status = fstat(fd, &s);
		if (status != 0 || !S_ISREG(s.st_mode))
		{
			if (error != NULL)
			{
				if (!S_ISREG(s.st_mode))
				{
					strlcpy(error, "Not a regular file",
					        errlen);
				}
				else
				{
					strlcpy(error, strerror(errno),
					        errlen);
				}
			}
			close(fd);
			return FALSE;
		}

		if (!dkimf_securefile(buf, &ino, (uid_t) -1, error, errlen) ||
		    (ino != (ino_t) -1 && ino != s.st_ino))
			*insecure = TRUE;
		else
			*insecure = FALSE;

		*buflen = MIN(s.st_size, *buflen);
		rlen = read(fd, buf, *buflen);
		close(fd);

		if (rlen < *buflen)
			return FALSE;
	}

	return TRUE;
}

/*
**  DKIMF_ADD_SIGNREQUEST -- add a signing request
**
**  Parameters:
**  	dfc -- message context
**  	keytable -- table from which to get key
**  	keyname -- name of private key to use
**  	signer -- signer identity to use
**  	signlen -- signature length
**
**  Return value:
**  	3 -- substitution token provided but domain not provided
**  	2 -- requested key could not be loaded
**  	1 -- requested key not found
**  	0 -- requested key added
**  	-1 -- requested key found but add failed (memory? or format)
*/

static int
dkimf_add_signrequest(struct msgctx *dfc, DKIMF_DB keytable, char *keyname,
                      char *signer, ssize_t signlen)
{
	_Bool found = FALSE;
	size_t keydatasz = 0;
	struct signreq *new;
	struct dkimf_db_data dbd[3];
	char keydata[MAXBUFRSZ + 1];
	char domain[DKIM_MAXHOSTNAMELEN + 1];
	char selector[BUFRSZ + 1];
	char err[BUFRSZ + 1];

	assert(dfc != NULL);

	/*
	**  Error out if we want the default key but the key or selector were
	**  not provided.
	*/

	if (keyname == NULL)
	{
		if (curconf->conf_seckey == NULL ||
		    curconf->conf_selector == NULL)
			return 1;
	}

	if (keytable != NULL)
	{
		_Bool insecure;

		assert(keyname != NULL);

		memset(domain, '\0', sizeof domain);
		memset(selector, '\0', sizeof selector);
		memset(keydata, '\0', sizeof keydata);

		dbd[0].dbdata_buffer = domain;
		dbd[0].dbdata_buflen = sizeof domain - 1;
		dbd[0].dbdata_flags = DKIMF_DB_DATA_OPTIONAL;
		dbd[1].dbdata_buffer = selector;
		dbd[1].dbdata_buflen = sizeof selector - 1;
		dbd[1].dbdata_flags = DKIMF_DB_DATA_OPTIONAL;
		dbd[2].dbdata_buffer = keydata;
		dbd[2].dbdata_buflen = sizeof keydata - 1;
		dbd[2].dbdata_flags = DKIMF_DB_DATA_OPTIONAL;

		if (dkimf_db_get(keytable, keyname, strlen(keyname),
		                 dbd, 3, &found) != 0)
		{
			memset(err, '\0', sizeof err);
			(void) dkimf_db_strerror(keytable, err, sizeof err);

			if (dolog)
			{
				if (err[0] != '\0')
				{
					syslog(LOG_ERR,
					       "key '%s': dkimf_db_get(): %s",
					       keyname, err);
				}
				else
				{
					syslog(LOG_ERR,
					       "key '%s': dkimf_db_get() failed",
					       keyname);
				}
			}

			return -1;
		}

		if (!found)
			return 1;

		if (dbd[0].dbdata_buflen == 0 ||
		    dbd[0].dbdata_buflen == (size_t) -1 ||
		    dbd[1].dbdata_buflen == 0 ||
		    dbd[1].dbdata_buflen == (size_t) -1 ||
		    dbd[2].dbdata_buflen == 0 ||
		    dbd[2].dbdata_buflen == (size_t) -1)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "KeyTable entry for '%s' corrupt",
				       keyname);
			}

			return 2;
		}

		if (domain[0] == '%' && domain[1] == '\0' &&
		    dfc->mctx_domain == NULL)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "KeyTable entry for '%s' cannot be resolved",
				       keyname);
			}

			return 3;
		}

		if (keydata[0] == '/')
		{
			char *d;
			char tmpdata[MAXBUFRSZ + 1];

			memset(tmpdata, '\0', sizeof tmpdata);

			if (domain[0] == '%' && domain[1] == '\0')
				d = dfc->mctx_domain;
			else
				d = domain;

			dkimf_reptoken(tmpdata, sizeof tmpdata, keydata, d);

			memcpy(keydata, tmpdata, sizeof keydata);
		}

		keydatasz = sizeof keydata - 1;
		insecure = FALSE;
		if (!dkimf_loadkey(dbd[2].dbdata_buffer, &keydatasz,
		                   &insecure, err, sizeof err))
		{
			if (dolog)
			{
				syslog(LOG_ERR, "can't load key from %s: %s",
				       dbd[2].dbdata_buffer, err);
			}

			return 2;
		}

		if (insecure)
		{
			if (dolog)
			{
				int sev;

				sev = (curconf->conf_safekeys ? LOG_ERR
				                              : LOG_WARNING);

				syslog(sev, "%s: key data is not secure: %s",
				       keyname, err);
			}

 			if (curconf->conf_safekeys)
				return 2;
		}
	}

	new = malloc(sizeof *new);
	if (new == NULL)
		return -1;

	new->srq_next = NULL;
	new->srq_dkim = NULL;
	new->srq_domain = NULL;
	new->srq_selector = NULL;
	new->srq_keydata = NULL;
	new->srq_signlen = signlen;
	if (signer != NULL && signer[0] != '\0')
		new->srq_signer = (u_char *) strdup(signer);
	else
		new->srq_signer = NULL;

	if (keytable != NULL)
	{
		if (domain[0] == '%' && domain[1] == '\0')
			new->srq_domain = (u_char *) strdup((char *) dfc->mctx_domain);
		else
			new->srq_domain = (u_char *) strdup((char *) domain);

		new->srq_selector = (u_char *) strdup((char *) selector);
		new->srq_keydata = (void *) malloc(keydatasz + 1);
		if (new->srq_keydata == NULL)
		{
			free(new);
			return -1;
		}
		memset(new->srq_keydata, '\0', keydatasz + 1);
		memcpy(new->srq_keydata, dbd[2].dbdata_buffer, keydatasz);
	}

	if (dfc->mctx_srtail != NULL)
		dfc->mctx_srtail->srq_next = new;
	else
		dfc->mctx_srtail = new;

	if (dfc->mctx_srhead == NULL)
		dfc->mctx_srhead = new;

	return 0;
}

/*
**  DKIMF_MSR_HEADER -- process headers for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**  	last -- last handle processed (returned on error)
**  	header -- header field name and value
**  	headerlen -- number of bytes at "header"
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_header(struct signreq *sr, DKIM **last, u_char *header,
                 size_t headerlen)
{
	DKIM_STAT status;

	assert(sr != NULL);
	assert(header != NULL);

	while (sr != NULL)
	{
		status = dkim_header(sr->srq_dkim, header, headerlen);
		if (status != DKIM_STAT_OK)
		{
			if (last != NULL)
				*last = sr->srq_dkim;
			return status;
		}
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_MSR_EOH -- process end-of-headers for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
** 	last -- last DKIM handle processed (returned on error)
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_eoh(struct signreq *sr, DKIM **last)
{
	DKIM_STAT status;

	assert(sr != NULL);

	while (sr != NULL)
	{
		status = dkim_eoh(sr->srq_dkim);
		if (status != DKIM_STAT_OK)
		{
			if (last != NULL)
				*last = sr->srq_dkim;
			return status;
		}
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_MSR_BODY -- process a body chunk for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**  	last -- last DKIM handle processed (returned on error)
**  	body -- body chunk
**  	bodylen -- body length
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_body(struct signreq *sr, DKIM **last, u_char *body, size_t bodylen)
{
	DKIM_STAT status;

	assert(sr != NULL);
	assert(body != NULL);

	while (sr != NULL)
	{
		status = dkim_body(sr->srq_dkim, body, bodylen);
		if (status != DKIM_STAT_OK)
		{
			if (last != NULL)
				*last = sr->srq_dkim;
			return status;
		}

		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_MSR_MINBODY -- determine minimum body required to satisfy all
**                       all open canonicalizations
**
**  Parameters:
**  	srh -- head of the signature request list
**
**  Return value:
**  	Maximum of all dkim_minbody() returns.
*/

static int
dkimf_msr_minbody(struct signreq *sr)
{
	u_long mb = 0;
	u_long ret = 0;

	assert(sr != NULL);

	while (sr != NULL)
	{
		ret = dkim_minbody(sr->srq_dkim);
		if (ret > mb)
			mb = ret;
		sr = sr->srq_next;
	}

	return mb;;
}

/*
**  DKIMF_MSR_EOM -- process end-of-message for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**  	last -- last DKIM handle processed (returned)
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_eom(struct signreq *sr, DKIM **last)
{
	_Bool testkey;
	DKIM_STAT status;

	assert(sr != NULL);

	while (sr != NULL)
	{
		status = dkim_eom(sr->srq_dkim, &testkey);
		if (status != DKIM_STAT_OK)
		{
			if (last != NULL)
				*last = sr->srq_dkim;
			return status;
		}
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_PRESCREEN -- check signatures against third-party limitations
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sigs -- array of signatures
**  	nsigs -- size of signature array
**
**  Return value:
**  	DKIM_CBSTAT_CONTINUE
*/

static DKIM_CBSTAT
dkimf_prescreen(DKIM *dkim, DKIM_SIGINFO **sigs, int nsigs)
{
	int c;
	unsigned int ni = 0;
	u_char *domain;
	u_char *sdomain;
	SMFICTX *ctx;
	connctx cc;
	msgctx dfc;
	struct dkimf_config *conf;

	ctx = (SMFICTX *) dkim_get_user_context(dkim);
	cc = (connctx) dkimf_getpriv(ctx);
	conf = cc->cctx_config;
	dfc = cc->cctx_msg;
	domain = dkim_getdomain(dkim);

	if (conf->conf_maxverify > 0)
	{
		int n;
		_Bool *ig = NULL;

		ig = (_Bool *) malloc(sizeof(_Bool) * nsigs);
		if (ig == NULL)
			return DKIM_CBSTAT_ERROR;

		/* mark everything to be ignored */
		for (c = 0; c < nsigs; c++)
			ig[c] = TRUE;

		n = conf->conf_maxverify;

		if (conf->conf_thirdpartydb != NULL)
		{
			_Bool found;

			/* unmark sigs that are explicitly trusted */
			for (c = 0; c < nsigs; c++)
			{
				sdomain = dkim_sig_getdomain(sigs[c]);

				found = FALSE;

				if (dkimf_db_get(conf->conf_thirdpartydb,
				                 (char *) sdomain, 0, NULL, 0,
				                 &found) != 0)
				{
					free(ig);
					return DKIM_CBSTAT_ERROR;
				}

				if (found)
				{
					ig[c] = FALSE;
					n--;
				}
			}
		}

		/* unmark from the top down any that don't exceed the limit */
		for (c = 0; c < nsigs && n > 0; c++)
		{
			if (ig[c])
			{
				n--;
				ig[c] = FALSE;
			}
		}

		/* mark what's left to be ignored */
		for (c = 0; c < nsigs; c++)
		{
			if (ig[c])
			{
				dkim_sig_ignore(sigs[c]);
				ni++;
			}
		}

		if (conf->conf_dolog && ni > 0)
		{
			syslog(LOG_INFO, "%s: ignoring %u signature%s",
			       dkim_getid(dkim), ni, ni == 1 ? "" : "s");
		}

		free(ig);

		return DKIM_CBSTAT_CONTINUE;
	}

	/* ignore signatures which are neither first-party nor trusted */
	for (c = 0; c < nsigs; c++)
	{
		sdomain = dkim_sig_getdomain(sigs[c]);

		/* author domain */
		if (strcasecmp((char *) sdomain, (char *) domain) == 0)
			continue;

		/* trusted third party domain */
		if (conf->conf_thirdpartydb != NULL)
		{
			_Bool found = FALSE;

			if (dkimf_db_get(conf->conf_thirdpartydb,
			                    (char *) sdomain, 0, NULL, 0,
			                    &found) != 0)
				return DKIM_CBSTAT_ERROR;

			if (found)
				continue;
		}

		/* neither; arrange to ignore it */
		dkim_sig_ignore(sigs[c]);

		if (conf->conf_dolog)
		{
			syslog(LOG_INFO, "%s: ignoring signature from %s",
			       dfc->mctx_jobid, sdomain);
		}
	}

	return DKIM_CBSTAT_CONTINUE;
}

/*
**  DKIMF_ARFTYPE -- return ARF message type to report
**
**  Parameters:
**  	dfc -- DKIM filter context
**
**  Return value:
**  	An ARF_TYPE_* constant.
*/

static int
dkimf_arftype(msgctx dfc)
{
	assert(dfc != NULL);

	if (dfc->mctx_susp)
		return ARF_TYPE_FRAUD;
	else
		return ARF_TYPE_AUTHFAIL;
}

/*
**  DKIMF_ARFDKIM -- return an appropriate ARF DKIM failure code
**
**  Parameters:
**  	dfc -- DKIM filter context
**
**  Return value:
**  	An ARF_DKIMF_* constant.
*/

static int
dkimf_arfdkim(msgctx dfc)
{
	DKIM_SIGINFO *sig;

	assert(dfc != NULL);

	sig = dkim_getsignature(dfc->mctx_dkimv);
	if (sig == NULL)
		return ARF_DKIMF_UNKNOWN;

	if (dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
		return ARF_DKIMF_BODYHASH;

	switch (dkim_sig_geterror(sig))
	{
	  case DKIM_SIGERROR_BADSIG:
		return ARF_DKIMF_SIGNATURE;

	  case DKIM_SIGERROR_KEYREVOKED:
		return ARF_DKIMF_REVOKED;

	  case DKIM_SIGERROR_VERSION:
	  case DKIM_SIGERROR_INVALID_HC:
	  case DKIM_SIGERROR_INVALID_BC:
	  case DKIM_SIGERROR_MISSING_A:
	  case DKIM_SIGERROR_INVALID_A:
	  case DKIM_SIGERROR_MISSING_H:
	  case DKIM_SIGERROR_INVALID_L:
	  case DKIM_SIGERROR_INVALID_Q:
	  case DKIM_SIGERROR_INVALID_QO:
	  case DKIM_SIGERROR_MISSING_D:
	  case DKIM_SIGERROR_EMPTY_D:
	  case DKIM_SIGERROR_MISSING_S:
	  case DKIM_SIGERROR_EMPTY_S:
	  case DKIM_SIGERROR_MISSING_B:
	  case DKIM_SIGERROR_EMPTY_B:
	  case DKIM_SIGERROR_CORRUPT_B:
	  case DKIM_SIGERROR_DNSSYNTAX:
	  case DKIM_SIGERROR_MISSING_BH:
	  case DKIM_SIGERROR_EMPTY_BH:
	  case DKIM_SIGERROR_CORRUPT_BH:
	  case DKIM_SIGERROR_MULTIREPLY:
	  case DKIM_SIGERROR_EMPTY_H:
	  case DKIM_SIGERROR_INVALID_H:
	  case DKIM_SIGERROR_TOOLARGE_L:
	  case DKIM_SIGERROR_KEYVERSION:
	  case DKIM_SIGERROR_KEYUNKNOWNHASH:
	  case DKIM_SIGERROR_KEYTYPEMISSING:
	  case DKIM_SIGERROR_KEYTYPEUNKNOWN:
		return ARF_DKIMF_SYNTAX;

	  default:
		return ARF_DKIMF_OTHER;
	}
}

/*
**  DKIMF_REPORTADDR -- set reporting address
**
**  Parameters:
**  	conf -- current configuration
**
**  Return value:
**  	None.
*/

static void
dkimf_reportaddr(struct dkimf_config *conf)
{
	uid_t uid;
	struct passwd *pw;
	assert(conf != NULL);

	if (conf->conf_reportaddr != NULL)
	{
		int status;
		u_char *user;
		u_char *domain;
		u_char env[MAXADDRESS + 1];	/* reporting address */

		strlcpy(reportaddr, conf->conf_reportaddr, sizeof reportaddr);
		strlcpy((char *) env, conf->conf_reportaddr,
		        sizeof reportaddr);
		status = dkim_mail_parse(env, &user, &domain);
		if (status == 0 && user != NULL && domain != NULL)
		{
			snprintf(reportcmd, sizeof reportcmd,
			         "%s -t -f%s@%s",
			         conf->conf_mtacommand, user, domain);

			return;
		}
		else
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "error parsing ReportAddress; using default");
			}
		}
	}

	/* not successful case has already returned. Make up a value if not
	 * set of an error occurs */

	uid = geteuid();
	pw = getpwuid(uid);

	if (pw == NULL)
	{
		snprintf(reportaddr, sizeof reportaddr,
		         "%u@%s", uid, myhostname);
	}
	else
	{
		snprintf(reportaddr, sizeof reportaddr,
		         "%s@%s", pw->pw_name, myhostname);
	}

	snprintf(reportcmd, sizeof reportcmd, "%s -t -f%s",
	         conf->conf_mtacommand, reportaddr);
}

/*
**  DKIMF_LOOKUP_STRTOINT -- look up the integer code for a config option
**                           or value
**
**  Parameters:
**  	opt -- option to look up
**  	table -- lookup table to use
**
**  Return value:
**  	Integer version of the option, or -1 on error.
*/

static int
dkimf_lookup_strtoint(char *opt, struct lookup *table)
{
	int c;

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL ||
		    strcasecmp(opt, table[c].str) == 0)
			return table[c].code;
	}
}

/*
**  DKIMF_LOOKUP_INTTOSTR -- look up the string matching an internal code
**
**  Parameters:
**  	code -- code to look up
**  	table -- lookup table to use
**
**  Return value:
**  	String version of the option, or NULL on error.
*/

static const char *
dkimf_lookup_inttostr(int code, struct lookup *table)
{
	int c;

	for (c = 0; ; c++)
	{
		if (table[c].code == -1 || table[c].code == code)
			return table[c].str;
	}

	assert(0);
	/* NOTREACHED */
}

/*
**  DKIMF_GETDKIM -- retrieve DKIM handle in use
**
**  Parameters:
**  	vp -- opaque pointer (from test.c)
**
**  Return value:
**  	DKIM handle in use, or NULL.
*/

DKIM *
dkimf_getdkim(void *vp)
{
	struct connctx *cc;

	assert(vp != NULL);

	cc = vp;
	if (cc->cctx_msg != NULL)
		return cc->cctx_msg->mctx_dkimv;
	else
		return NULL;
}

/*
**  DKIMF_GETSRLIST -- retrieve signing request list
**
**  Parameters:
**  	vp -- opaque pointer (from test.c)
**
**  Return value:
**  	Head of the signing request list.
*/

struct signreq *
dkimf_getsrlist(void *vp)
{
	struct connctx *cc;

	assert(vp != NULL);

	cc = vp;
	if (cc->cctx_msg != NULL)
		return cc->cctx_msg->mctx_srhead;
	else
		return NULL;
}

/*
**  DKIMF_SIGHANDLER -- signal handler
**
**  Parameters:
**  	sig -- signal received
**
**  Return value:
**  	None.
*/

static void
dkimf_sighandler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM || sig == SIGHUP)
	{
		diesig = sig;
		die = TRUE;
	}
	else if (sig == SIGUSR1 && !die)
	{
		if (conffile != NULL)
			reload = TRUE;
	}
}

/*
**  DKIMF_RELOADER -- reload signal thread
**
**  Parameters:
**  	vp -- void pointer required by thread API but not used
**
**  Return value:
**  	NULL.
*/

static void *
dkimf_reloader(/* UNUSED */ void *vp)
{
	int sig;
	sigset_t mask;

	(void) pthread_detach(pthread_self());

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);

	while (!die)
	{
		(void) sigwait(&mask, &sig);

		if (conffile != NULL)
			reload = TRUE;
	}

	return NULL;
}

/*
**  DKIMF_KILLCHILD -- kill child process
**
**  Parameters:
**  	pid -- process ID to signal
**  	sig -- signal to use
**  	dolog -- log it?
**
**  Return value:
**  	None.
*/

static void
dkimf_killchild(pid_t pid, int sig, _Bool dolog)
{
	if (kill(pid, sig) == -1 && dolog)
	{
		syslog(LOG_ERR, "kill(%d, %d): %s", pid, sig,
		       strerror(errno));
	}
}

/*
**  DKIMF_ZAPKEY -- clobber the copy of the private key
**
**  Parameters:
**  	conf -- configuration handle in which to clobber the key
**
**  Return value:
**  	None.
*/

static void
dkimf_zapkey(struct dkimf_config *conf)
{
	assert(conf != NULL);

	if (conf->conf_seckey != NULL)
	{
		memset(conf->conf_seckey, '\0', conf->conf_keylen);
		free(conf->conf_seckey);
		conf->conf_seckey = NULL;
	}
}

/*
**  DKIMF_AUTHORSIGOK -- return TRUE iff a message was signed with an
**                       author signature that passed
**
**  Parameters:
**  	msg -- a message context handle
**
**  Return value:
**  	TRUE iff the message referenced by "dkim" was signed with an
**  	author signature and that signature passed.
*/

static _Bool
dkimf_authorsigok(msgctx msg)
{
	DKIM_STAT status;
	int c;
	int nsigs;
	DKIM_SIGINFO **sigs;

	assert(msg != NULL);

	status = dkim_getsiglist(msg->mctx_dkimv, &sigs, &nsigs);
	if (status != DKIM_STAT_OK)
		return FALSE;

	for (c = 0; c < nsigs; c++)
	{
		/* skip signatures with errors */
		if (dkim_sig_geterror(sigs[c]) != DKIM_SIGERROR_UNKNOWN &&
		    dkim_sig_geterror(sigs[c]) != DKIM_SIGERROR_OK)
			continue;

		if (strcasecmp((char *) dkim_sig_getdomain(sigs[c]),
		               (char *) msg->mctx_domain) == 0 &&
		    (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) != 0 &&
		    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH)
			return TRUE;
	}

	return FALSE;
}

/*
**  DKIMF_CONFIG_NEW -- get a new configuration handle
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new configuration handle, or NULL on error.
*/

static struct dkimf_config *
dkimf_config_new(void)
{
	struct dkimf_config *new;

	new = (struct dkimf_config *) malloc(sizeof(struct dkimf_config));
	if (new == NULL)
		return NULL;

	memset(new, '\0', sizeof(struct dkimf_config));
	new->conf_hdrcanon = DKIM_CANON_DEFAULT;
	new->conf_bodycanon = DKIM_CANON_DEFAULT;
	new->conf_dnstimeout = DEFTIMEOUT;
	new->conf_maxverify = DEFMAXVERIFY;
	new->conf_maxhdrsz = DEFMAXHDRSZ;
	new->conf_signbytes = -1L;
	new->conf_sigmintype = SIGMIN_BYTES;
#ifdef _FFR_REPUTATION
	new->conf_repfactor = DKIMF_REP_DEFFACTOR;
	new->conf_repcachettl = DKIMF_REP_DEFCACHETTL;
#endif /* _FFR_REPUTATION */
	new->conf_safekeys = TRUE;
#ifdef _FFR_STATS
	new->conf_reporthost = myhostname;
#endif /* _FFR_STATS */
#ifdef _FFR_RATE_LIMIT
	new->conf_flowdatattl = DEFFLOWDATATTL;
	new->conf_flowfactor = 1;
#endif /* _FFR_RATE_LIMIT */
	new->conf_mtacommand = SENDMAIL_PATH;
#ifdef _FFR_ATPS
	new->conf_atpshash = dkimf_atpshash[0].str;
#endif /* _FFR_ATPS */
	new->conf_selectcanonhdr = SELECTCANONHDR;

	memcpy(&new->conf_handling, &defaults, sizeof new->conf_handling);

	return new;
}

/*
**  DKIMF_CONFIG_FREE -- destroy a configuration handle
**
**  Parameters:
**  	conf -- pointer to the configuration handle to be destroyed
**
**  Return value:
**  	None.
*/

static void
dkimf_config_free(struct dkimf_config *conf)
{
	assert(conf != NULL);
	assert(conf->conf_refcnt == 0);

	dkimf_zapkey(conf);

	if (conf->conf_libopendkim != NULL)
		dkim_close(conf->conf_libopendkim);

	if (conf->conf_testdnsdb != NULL)
		dkimf_db_close(conf->conf_testdnsdb);

	if (conf->conf_domainsdb != NULL)
		dkimf_db_close(conf->conf_domainsdb);

	if (conf->conf_bldb != NULL)
		dkimf_db_close(conf->conf_bldb);

	if (conf->conf_domlist != NULL)
		free(conf->conf_domlist);

	if (conf->conf_omithdrdb != NULL)
		dkimf_db_close(conf->conf_omithdrdb);

	if (conf->conf_thirdpartydb != NULL)
		dkimf_db_close(conf->conf_thirdpartydb);

	if (conf->conf_signhdrsdb != NULL)
		dkimf_db_close(conf->conf_signhdrsdb);

	if (conf->conf_senderhdrsdb != NULL)
		dkimf_db_close(conf->conf_senderhdrsdb);

	if (conf->conf_oversigndb != NULL)
		dkimf_db_close(conf->conf_oversigndb);

	if (conf->conf_mtasdb != NULL)
		dkimf_db_close(conf->conf_mtasdb);

	if (conf->conf_macrosdb != NULL)
		dkimf_db_close(conf->conf_macrosdb);

	if (conf->conf_mbsdb != NULL)
		dkimf_db_close(conf->conf_mbsdb);

	if (conf->conf_dontsigntodb != NULL)
		dkimf_db_close(conf->conf_dontsigntodb);

#ifdef _FFR_ATPS
	if (conf->conf_atpsdb != NULL)
		dkimf_db_close(conf->conf_atpsdb);
#endif /* _FFR_ATPS */

	if (conf->conf_authservid != NULL)
		free(conf->conf_authservid);

	if (conf->conf_peerdb != NULL)
		dkimf_db_close(conf->conf_peerdb);

	if (conf->conf_internal != NULL)
		dkimf_db_close(conf->conf_internal);

	if (conf->conf_exignore != NULL)
		dkimf_db_close(conf->conf_exignore);

	if (conf->conf_exemptdb != NULL)
		dkimf_db_close(conf->conf_exemptdb);

#ifdef _FFR_REPLACE_RULES
	if (conf->conf_replist != NULL)
		dkimf_free_replist(conf->conf_replist);
	if (conf->conf_rephdrsdb != NULL)
		dkimf_db_close(conf->conf_rephdrsdb);
#endif /* _FFR_REPLACE_RULES */

#ifdef _FFR_VBR
	if (conf->conf_vbr_trusteddb != NULL)
		dkimf_db_close(conf->conf_vbr_trusteddb);
#endif /* _FFR_VBR */

	if (conf->conf_nosignpats != NULL)
	{
		int n;

		for (n = 0; conf->conf_nosignpats[n] != NULL; n++)
			regfree(conf->conf_nosignpats[n]);

		free(conf->conf_nosignpats);
	}

#ifdef _FFR_RESIGN
	if (conf->conf_resigndb != NULL)
		dkimf_db_close(conf->conf_resigndb);
#endif /* _FFR_RESIGN */

#ifdef _FFR_RATE_LIMIT
	if (conf->conf_ratelimitdb != NULL)
		dkimf_db_close(conf->conf_ratelimitdb);
	if (conf->conf_flowdatadb != NULL)
		dkimf_db_close(conf->conf_flowdatadb);
#endif /* _FFR_RATE_LIMIT */

#ifdef _FFR_REPUTATION
	if (conf->conf_repratiosdb != NULL)
		dkimf_db_close(conf->conf_repratiosdb);
	if (conf->conf_replimitsdb != NULL)
		dkimf_db_close(conf->conf_replimitsdb);
	if (conf->conf_replimitmodsdb != NULL)
		dkimf_db_close(conf->conf_replimitmodsdb);
	if (conf->conf_repspamcheck != NULL)
		regfree(&conf->conf_repspamre);
	if (conf->conf_rep != NULL)
		dkimf_rep_close(conf->conf_rep);
#endif /* _FFR_REPUTATION */

#ifdef _FFR_REPRRD
	if (conf->conf_reprrd != NULL)
		reprrd_close(conf->conf_reprrd);
#endif /* _FFR_REPRRD */

#ifdef USE_LUA
	if (conf->conf_setupscript != NULL)
		free(conf->conf_setupscript);
	if (conf->conf_setupfunc != NULL)
		free(conf->conf_setupfunc);
	if (conf->conf_screenscript != NULL)
		free(conf->conf_screenscript);
	if (conf->conf_screenfunc != NULL)
		free(conf->conf_screenfunc);
# ifdef _FFR_STATSEXT
	if (conf->conf_statsscript != NULL)
		free(conf->conf_statsscript);
	if (conf->conf_statsfunc != NULL)
		free(conf->conf_statsfunc);
# endif /* _FFR_STATSEXT */
	if (conf->conf_finalscript != NULL)
		free(conf->conf_finalscript);
	if (conf->conf_finalfunc != NULL)
		free(conf->conf_finalfunc);
#endif /* USE_LUA */

	if (conf->conf_keytabledb != NULL)
		dkimf_db_close(conf->conf_keytabledb);
	if (conf->conf_signtabledb != NULL)
		dkimf_db_close(conf->conf_signtabledb);

	if (conf->conf_data != NULL)
		config_free(conf->conf_data);

	free(conf);
}

/*
**  DKIMF_PARSEHANDLER -- parse a handler
**
**  Parameters:
**  	cfg -- configuration data structure to check
**  	name -- handler name
**  	hndl -- handler structure to update
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	TRUE if no error, FALSE if error.
*/

static _Bool
dkimf_parsehandler(struct config *cfg, char *name, struct handling *hndl,
                   char *err, size_t errlen)
{
	int action;
	char *val = NULL;

	assert(name != NULL);
	assert(strncasecmp(name, "on-", 3) == 0);
	assert(hndl != NULL);
	assert(err != NULL);

	if (cfg == NULL)
		return TRUE;

	(void) config_get(cfg, name, &val, sizeof val);

	if (val == NULL)
		return TRUE;

	action = dkimf_lookup_strtoint(val, dkimf_values);
	if (action == -1) {
		snprintf(err, errlen, "invalid handling value \"%s\"", val);
		return -1;
	}

	switch (dkimf_lookup_strtoint(name + 3, dkimf_params))
	{
	  case HNDL_DEFAULT:
		hndl->hndl_nosig = action;
		hndl->hndl_badsig = action;
		hndl->hndl_dnserr = action;
		hndl->hndl_internal = action;
		hndl->hndl_security = action;
		hndl->hndl_nokey = action;
#if defined(_FFR_REPUTATION) || defined(_FFR_REPRRD)
		hndl->hndl_reperr = action;
#endif /* _FFR_REPUTATION || defined(_FFR_REPRRD) */
		hndl->hndl_siggen = action;
		return TRUE;

	  case HNDL_NOSIGNATURE:
		hndl->hndl_nosig = action;
		return TRUE;

	  case HNDL_BADSIGNATURE:
		hndl->hndl_badsig = action;
		return TRUE;

	  case HNDL_DNSERROR:
		hndl->hndl_dnserr = action;
		return TRUE;

	  case HNDL_INTERNAL:
		hndl->hndl_internal = action;
		return TRUE;

	  case HNDL_SECURITY:
		hndl->hndl_security = action;
		return TRUE;

	  case HNDL_NOKEY:
		hndl->hndl_nokey = action;
		return TRUE;

#if defined(_FFR_REPUTATION) || defined(_FFR_REPRRD)
	  case HNDL_REPERROR:
		hndl->hndl_reperr = action;
		return TRUE;
#endif /* _FFR_REPUTATION || defined(_FFR_REPRRD) */

	  case HNDL_SIGGEN:
		hndl->hndl_siggen = action;
		return TRUE;

	  default:
		snprintf(err, errlen, "unknown handling key \"%s\"", name);
		return FALSE;
	}
}

/*
**  DKIMF_CONFIG_LOAD -- load a configuration handle based on file content
**
**  Paramters:
**  	data -- configuration data loaded from config file
**  	conf -- configuration structure to load
**  	err -- where to write errors
**  	errlen -- bytes available at "err"
**  	become -- pretend we're the named user (can be NULL)
**
**  Return value:
**  	0 -- success
**  	!0 -- error
**
**  Side effects:
**  	openlog() may be called by this function
*/

static int
dkimf_config_load(struct config *data, struct dkimf_config *conf,
                  char *err, size_t errlen, char *become)
{
#ifdef USE_LDAP
	_Bool btmp;
#endif /* USE_LDAP */
	int maxsign;
	int dbflags = 0;
	char *str;
	char confstr[BUFRSZ + 1];
	char basedir[MAXPATHLEN + 1];

	assert(conf != NULL);
	assert(err != NULL);

	memset(basedir, '\0', sizeof basedir);
	memset(confstr, '\0', sizeof confstr);

	if (data != NULL)
	{
		int tmpint;

#ifdef USE_LDAP
		(void) config_get(data, "LDAPSoftStart",
		                  &conf->conf_softstart,
		                  sizeof conf->conf_softstart);
#endif /* USE_LDAP */

		(void) config_get(data, "DNSConnect",
		                  &conf->conf_dnsconnect,
		                  sizeof conf->conf_dnsconnect);

		(void) config_get(data, "ResolverTracing",
		                  &conf->conf_restrace,
		                  sizeof conf->conf_restrace);

		(void) config_get(data, "AlwaysAddARHeader",
		                  &conf->conf_alwaysaddar,
		                  sizeof conf->conf_alwaysaddar);

		str = NULL;
		(void) config_get(data, "AuthservID", &str, sizeof str);
		if (str != NULL)
		{
			if (strcmp(str, "HOSTNAME") == 0)
				conf->conf_authservid = strdup(myhostname);
			else	
				conf->conf_authservid = strdup(str);
		}

		(void) config_get(data, "AuthservIDWithJobID",
		                  &conf->conf_authservidwithjobid,
		                  sizeof conf->conf_authservidwithjobid);

#ifdef HAVE_CURL_EASY_STRERROR
		(void) config_get(data, "SMTPURI", &conf->conf_smtpuri,
		                  sizeof conf->conf_smtpuri);
#endif /* HAVE_CURL_EASY_STRERROR */

		str = NULL;
		(void) config_get(data, "BaseDirectory", &str, sizeof str);
		if (str != NULL)
			strlcpy(basedir, str, sizeof basedir);

		if (conf->conf_canonstr == NULL)
		{
			(void) config_get(data, "Canonicalization",
			                  &conf->conf_canonstr,
			                  sizeof conf->conf_canonstr);
		}

		(void) config_get(data, "ClockDrift", &conf->conf_clockdrift,
		                  sizeof conf->conf_clockdrift);

#ifdef _FFR_DEFAULT_SENDER
		(void) config_get(data, "DefaultSender", &conf->conf_defsender,
		                  sizeof conf->conf_defsender);
#endif /* _FFR_DEFAULT_SENDER */

		(void) config_get(data, "Diagnostics", &conf->conf_ztags,
		                  sizeof conf->conf_ztags);

		(void) config_get(data, "DiagnosticDirectory",
		                  &conf->conf_diagdir,
		                  sizeof conf->conf_diagdir);

		(void) config_get(data, "RedirectFailuresTo",
		                  &conf->conf_redirect,
		                  sizeof conf->conf_redirect);

#ifdef _FFR_RESIGN
		(void) config_get(data, "ResignMailTo",
		                  &conf->conf_resign,
		                  sizeof conf->conf_resign);
		(void) config_get(data, "ResignAll",
		                  &conf->conf_resignall,
		                  sizeof conf->conf_resignall);
#endif /* _FFR_RESIGN */

		if (conf->conf_dnstimeout == DEFTIMEOUT)
		{
			(void) config_get(data, "DNSTimeout",
			                  &conf->conf_dnstimeout,
			                  sizeof conf->conf_dnstimeout);
		}

		(void) config_get(data, "EnableCoredumps",
		                  &conf->conf_enablecores,
		                  sizeof conf->conf_enablecores);

		(void) config_get(data, "MinimumKeyBits",
		                  &conf->conf_minkeybits,
		                  sizeof conf->conf_minkeybits);

		(void) config_get(data, "RequestReports",
		                  &conf->conf_reqreports,
		                  sizeof conf->conf_reqreports);

		(void) config_get(data, "RequireSafeKeys",
		                  &conf->conf_safekeys,
		                  sizeof conf->conf_safekeys);

		(void) config_get(data, "TestDNSData",
		                  &conf->conf_testdnsdata,
		                  sizeof conf->conf_testdnsdata);

		(void) config_get(data, "NoHeaderB",
		                  &conf->conf_noheaderb,
		                  sizeof conf->conf_noheaderb);

		(void) config_get(data, "FixCRLF",
		                  &conf->conf_fixcrlf,
		                  sizeof conf->conf_fixcrlf);

		(void) config_get(data, "KeepTemporaryFiles",
		                  &conf->conf_keeptmpfiles,
		                  sizeof conf->conf_keeptmpfiles);

		(void) config_get(data, "StrictHeaders",
		                  &conf->conf_stricthdrs,
		                  sizeof conf->conf_stricthdrs);

		(void) config_get(data, "TemporaryDirectory",
		                  &conf->conf_tmpdir,
		                  sizeof conf->conf_tmpdir);

		(void) config_get(data, "MaximumHeaders", &conf->conf_maxhdrsz,
		                  sizeof conf->conf_maxhdrsz);

		(void) config_get(data, "MaximumSignaturesToVerify",
		                  &conf->conf_maxverify,
		                  sizeof conf->conf_maxverify);

#ifdef	_FFR_IDENTITY_HEADER
		(void) config_get(data, "IdentityHeader",
				  &conf->conf_identityhdr, 
				  sizeof conf->conf_identityhdr);

		(void) config_get(data, "IdentityHeaderRemove",
		                  &conf->conf_rmidentityhdr,
		                  sizeof conf->conf_rmidentityhdr);
#endif /* _FFR_IDENTITY_HEADER */

		if (conf->conf_siglimit == NULL)
		{
			(void) config_get(data, "Minimum",
			                  &conf->conf_siglimit,
			                  sizeof conf->conf_siglimit);
		}

		if (conf->conf_modestr == NULL)
		{
			(void) config_get(data, "Mode", &conf->conf_modestr,
			                  sizeof conf->conf_modestr);
		}

		if (!dkimf_parsehandler(data, "On-Default",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-BadSignature",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-DNSError",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-KeyNotFound",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-InternalError",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-NoSignature",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-PolicyError",
		                        &conf->conf_handling, err, errlen) ||
#ifdef _FFR_REPUTATION
		    !dkimf_parsehandler(data, "On-ReptuationError",
		                        &conf->conf_handling, err, errlen) ||
#endif /* _FFR_REPUTATION */
		    !dkimf_parsehandler(data, "On-Security",
		                        &conf->conf_handling, err, errlen) ||
		    !dkimf_parsehandler(data, "On-SignatureError",
		                        &conf->conf_handling, err, errlen))
			return -1;

		(void) config_get(data, "RemoveARAll", &conf->conf_remarall,
		                  sizeof conf->conf_remarall);

		(void) config_get(data, "KeepAuthResults", &conf->conf_keepar,
		                  sizeof conf->conf_keepar);

		(void) config_get(data, "RemoveOldSignatures",
		                  &conf->conf_remsigs,
		                  sizeof conf->conf_remsigs);

		if (!conf->conf_reqhdrs)
		{
			(void) config_get(data, "RequiredHeaders",
			                  &conf->conf_reqhdrs,
			                  sizeof conf->conf_reqhdrs);
		}

		if (conf->conf_selector == NULL)
		{
			(void) config_get(data, "Selector",
			                  &conf->conf_selector,
			                  sizeof conf->conf_selector);
		}

#ifdef _FFR_SENDER_MACRO
		if (conf->conf_sendermacro == NULL)
		{
			(void) config_get(data, "SenderMacro",
			                  &conf->conf_sendermacro,
			                  sizeof conf->conf_sendermacro);
		}
#endif /* _FFR_SENDER_MACRO */

		if (!conf->conf_sendreports)
		{
			(void) config_get(data, "SendReports",
			                  &conf->conf_sendreports,
			                  sizeof conf->conf_sendreports);
		}
		(void) config_get(data, "MTACommand",
		                  &conf->conf_mtacommand,
		                  sizeof conf->conf_mtacommand);

		(void) config_get(data, "ReportAddress",
		                  &conf->conf_reportaddr,
		                  sizeof conf->conf_reportaddr);

		(void) config_get(data, "ReportBccAddress",
		                  &conf->conf_reportaddrbcc,
		                  sizeof conf->conf_reportaddrbcc);

		if (conf->conf_signalgstr == NULL)
		{
			(void) config_get(data, "SignatureAlgorithm",
			                  &conf->conf_signalgstr,
			                  sizeof conf->conf_signalgstr);
		}

		tmpint = 0;
		(void) config_get(data, "SignatureTTL", &tmpint,
		                  sizeof tmpint);
		if (tmpint != 0)
			conf->conf_sigttl = (unsigned long) tmpint;

#ifdef _FFR_STATS
		(void) config_get(data, "Statistics", &conf->conf_statspath,
		                  sizeof conf->conf_statspath);

		(void) config_get(data, "StatisticsPrefix",
		                  &conf->conf_reportprefix,
		                  sizeof conf->conf_reportprefix);

		str = NULL;
		(void) config_get(data, "StatisticsName", &str, sizeof str);
		if (str != NULL)
			conf->conf_reporthost = str;
#endif /* _FFR_STATS */

		if (!conf->conf_subdomains)
		{
			(void) config_get(data, "SubDomains",
			                  &conf->conf_subdomains,
			                  sizeof conf->conf_subdomains);
		}

		if (!conf->conf_dolog)
		{
			(void) config_get(data, "Syslog", &conf->conf_dolog,
			                  sizeof conf->conf_dolog);
		}

		if (!conf->conf_logwhy)
		{
			(void) config_get(data, "LogWhy", &conf->conf_logwhy,
			                  sizeof conf->conf_logwhy);
		}

		(void) config_get(data, "LogResults", &conf->conf_logresults,
		                  sizeof conf->conf_logresults);

		(void) config_get(data, "MultipleSignatures",
		                  &conf->conf_multisig,
		                  sizeof conf->conf_multisig);

		(void) config_get(data, "SyslogSuccess",
		                  &conf->conf_dolog_success,
		                  sizeof conf->conf_dolog_success);

		(void) config_get(data, "WeakSyntaxChecks",
		                  &conf->conf_weaksyntax,
		                  sizeof conf->conf_weaksyntax);

#ifdef _FFR_LUA_ONLY_SIGNING
		(void) config_get(data, "LuaOnlySigning",
		                  &conf->conf_luasigning,
		                  sizeof conf->conf_luasigning);
#endif /* _FFR_LUA_ONLY_SIGNING */

		(void) config_get(data, "IgnoreMalformedMail",
		                  &conf->conf_passmalformed,
		                  sizeof conf->conf_passmalformed);

		(void) config_get(data, "DisableCryptoInit",
		                  &conf->conf_disablecryptoinit,
		                  sizeof conf->conf_disablecryptoinit);

		if (!conf->conf_addswhdr)
		{
			(void) config_get(data, "X-Header",
			                  &conf->conf_addswhdr,
			                  sizeof conf->conf_addswhdr);

			if (conf->conf_addswhdr)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_WARNING,
					       "\"X-Header\" deprecated; use \"SoftwareHeader\" instead");
				}
			}
			else
			{
				(void) config_get(data, "SoftwareHeader",
				                  &conf->conf_addswhdr,
				                  sizeof conf->conf_addswhdr);
			}
		}

		(void) config_get(data, "DomainKeysCompat",
		                  &conf->conf_acceptdk,
		                  sizeof conf->conf_acceptdk);

		(void) config_get(data, "CaptureUnknownErrors",
		                  &conf->conf_capture,
		                  sizeof conf->conf_capture);

#ifndef SMFIF_QUARANTINE
		if (conf->conf_capture)
		{
			strlcpy(err,
			        "quarantining not supported (required for CaptureUnknownErrors",
			        errlen);

			return -1;
		}
#endif /* SMFIF_QUARANTINE */

		(void) config_get(data, "AllowSHA1Only",
		                  &conf->conf_allowsha1only,
		                  sizeof conf->conf_allowsha1only);

#ifdef USE_LDAP
		btmp = FALSE;
		(void) config_get(data, "LDAPDisableCache", &btmp, sizeof btmp);
		if (btmp)
			dkimf_db_flags(DKIMF_DB_FLAG_NOCACHE);
		else
			dkimf_db_flags(0);

		(void) config_get(data, "LDAPUseTLS",
		                  &conf->conf_ldap_usetls,
		                  sizeof conf->conf_ldap_usetls);

		if (conf->conf_ldap_usetls)
			dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_USETLS, "y");
		else
			dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_USETLS, "n");

		(void) config_get(data, "LDAPTimeout",
		                  &conf->conf_ldap_timeout,
		                  sizeof conf->conf_ldap_timeout);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_TIMEOUT,
		                        conf->conf_ldap_timeout);

		(void) config_get(data, "LDAPKeepaliveIdle",
		                  &conf->conf_ldap_kaidle,
		                  sizeof conf->conf_ldap_kaidle);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_KA_IDLE,
		                        conf->conf_ldap_kaidle);

		(void) config_get(data, "LDAPKeepaliveProbes",
		                  &conf->conf_ldap_kaprobes,
		                  sizeof conf->conf_ldap_kaprobes);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_KA_PROBES,
		                        conf->conf_ldap_kaprobes);

		(void) config_get(data, "LDAPKeepaliveInterval",
		                  &conf->conf_ldap_kainterval,
		                  sizeof conf->conf_ldap_kainterval);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_KA_INTERVAL,
		                        conf->conf_ldap_kainterval);

		(void) config_get(data, "LDAPAuthMechanism",
		                  &conf->conf_ldap_authmech,
		                  sizeof conf->conf_ldap_authmech);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHMECH,
		                        conf->conf_ldap_authmech);

# ifdef USE_SASL
		(void) config_get(data, "LDAPAuthName",
		                  &conf->conf_ldap_authname,
		                  sizeof conf->conf_ldap_authname);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHNAME,
		                        conf->conf_ldap_authname);

		(void) config_get(data, "LDAPAuthRealm",
		                  &conf->conf_ldap_authrealm,
		                  sizeof conf->conf_ldap_authrealm);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHREALM,
		                        conf->conf_ldap_authrealm);

		(void) config_get(data, "LDAPAuthUser",
		                  &conf->conf_ldap_authuser,
		                  sizeof conf->conf_ldap_authuser);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_AUTHUSER,
		                        conf->conf_ldap_authuser);
# endif /* USE_SASL */

		(void) config_get(data, "LDAPBindPassword",
		                  &conf->conf_ldap_bindpw,
		                  sizeof conf->conf_ldap_bindpw);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_BINDPW,
		                        conf->conf_ldap_bindpw);

		(void) config_get(data, "LDAPBindUser",
		                  &conf->conf_ldap_binduser,
		                  sizeof conf->conf_ldap_binduser);

		dkimf_db_set_ldap_param(DKIMF_LDAP_PARAM_BINDUSER,
		                        conf->conf_ldap_binduser);
#endif /* USE_LDAP */

		(void) config_get(data, "Nameservers",
		                  &conf->conf_nslist,
		                  sizeof conf->conf_nslist);

		(void) config_get(data, "TrustAnchorFile",
		                  &conf->conf_trustanchorpath,
		                  sizeof conf->conf_trustanchorpath);

		if (conf->conf_trustanchorpath != NULL &&
		    access(conf->conf_trustanchorpath, R_OK) != 0)
		{
			snprintf(err, errlen, "%s: %s",
			         conf->conf_trustanchorpath, strerror(errno));
			return -1;
		}

		(void) config_get(data, "ResolverConfiguration",
		                  &conf->conf_resolverconfig,
		                  sizeof conf->conf_resolverconfig);

#ifdef USE_UNBOUND
		str = NULL;
		(void) config_get(data, "BogusKey", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_lookup_strtoint(str, dkimf_keyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown key action '%s'", str);
				return -1;
			}

			conf->conf_boguskey = c;
		}
		else
		{
			conf->conf_boguskey = DKIMF_KEYACTIONS_FAIL;
		}

		str = NULL;
		(void) config_get(data, "UnprotectedKey", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_lookup_strtoint(str, dkimf_keyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown key action '%s'", str);
				return -1;
			}

			conf->conf_unprotectedkey = c;
		}
		else
		{
			conf->conf_unprotectedkey = DKIMF_KEYACTIONS_NONE;
		}
#endif /* USE_UNBOUND */

#ifdef USE_LUA
		str = NULL;
		(void) config_get(data, "SetupPolicyScript", &str, sizeof str);
		if (str != NULL)
		{
			int fd;
			ssize_t rlen;
			struct stat s;
			struct dkimf_lua_script_result lres;

			fd = open(str, O_RDONLY, 0);
			if (fd < 0)
			{
				snprintf(err, errlen, "%s: open(): %s", str,
				         strerror(errno));
				return -1;
			}

			if (fstat(fd, &s) == -1)
			{
				snprintf(err, errlen, "%s: fstat(): %s", str,
				         strerror(errno));
				close(fd);
				return -1;
			}

			conf->conf_setupscript = malloc(s.st_size + 1);
			if (conf->conf_setupscript == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				close(fd);
				return -1;
			}

			memset(conf->conf_setupscript, '\0', s.st_size + 1);
			rlen = read(fd, conf->conf_setupscript, s.st_size);
			if (rlen == -1)
			{
				snprintf(err, errlen, "%s: read(): %s",
				         str, strerror(errno));
				close(fd);
				return -1;
			}
			else if (rlen < s.st_size)
			{
				snprintf(err, errlen, "%s: early EOF",
				         str);
				close(fd);
				return -1;
			}

			close(fd);

			memset(&lres, '\0', sizeof lres);
			if (dkimf_lua_setup_hook(NULL, conf->conf_setupscript,
			                         0, str, &lres,
			                         &conf->conf_setupfunc,
			                         &conf->conf_setupfuncsz) != 0)
			{
				strlcpy(err, lres.lrs_error, errlen);
				free(lres.lrs_error);
				return -1;
			}
		}

		str = NULL;
		(void) config_get(data, "ScreenPolicyScript",
		                  &str, sizeof str);
		if (str != NULL)
		{
			int fd;
			ssize_t rlen;
			struct stat s;
			struct dkimf_lua_script_result lres;

			fd = open(str, O_RDONLY, 0);
			if (fd < 0)
			{
				snprintf(err, errlen, "%s: open(): %s", str,
				         strerror(errno));
				return -1;
			}

			if (fstat(fd, &s) == -1)
			{
				snprintf(err, errlen, "%s: fstat(): %s", str,
				         strerror(errno));
				close(fd);
				return -1;
			}

			conf->conf_screenscript = malloc(s.st_size + 1);
			if (conf->conf_screenscript == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				close(fd);
				return -1;
			}

			memset(conf->conf_screenscript, '\0', s.st_size + 1);
			rlen = read(fd, conf->conf_screenscript, s.st_size);
			if (rlen == -1)
			{
				snprintf(err, errlen, "%s: read(): %s",
				         str, strerror(errno));
				close(fd);
				return -1;
			}
			else if (rlen < s.st_size)
			{
				snprintf(err, errlen, "%s: early EOF",
				         str);
				close(fd);
				return -1;
			}

			close(fd);

			memset(&lres, '\0', sizeof lres);
			if (dkimf_lua_screen_hook(NULL,
			                          conf->conf_screenscript, 0,
			                          str, &lres,
			                          &conf->conf_screenfunc,
			                          &conf->conf_screenfuncsz) != 0)
			{
				strlcpy(err, lres.lrs_error, errlen);
				free(lres.lrs_error);
				return -1;
			}
		}

# ifdef _FFR_STATSEXT
		str = NULL;
		(void) config_get(data, "StatisticsPolicyScript", &str,
		                  sizeof str);
		if (str != NULL)
		{
			int fd;
			ssize_t rlen;
			struct stat s;
			struct dkimf_lua_script_result lres;

			fd = open(str, O_RDONLY, 0);
			if (fd < 0)
			{
				snprintf(err, errlen, "%s: open(): %s", str,
				         strerror(errno));
				return -1;
			}

			if (fstat(fd, &s) == -1)
			{
				snprintf(err, errlen, "%s: fstat(): %s", str,
				         strerror(errno));
				close(fd);
				return -1;
			}

			conf->conf_statsscript = malloc(s.st_size + 1);
			if (conf->conf_statsscript == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				close(fd);
				return -1;
			}

			memset(conf->conf_statsscript, '\0', s.st_size + 1);
			rlen = read(fd, conf->conf_statsscript, s.st_size);
			if (rlen == -1)
			{
				snprintf(err, errlen, "%s: read(): %s",
				         str, strerror(errno));
				close(fd);
				return -1;
			}
			else if (rlen < s.st_size)
			{
				snprintf(err, errlen, "%s: early EOF",
				         str);
				close(fd);
				return -1;
			}

			close(fd);

			memset(&lres, '\0', sizeof lres);
			if (dkimf_lua_stats_hook(NULL, conf->conf_statsscript,
			                         0, str, &lres,
			                         &conf->conf_statsfunc,
			                         &conf->conf_statsfuncsz) != 0)
			{
				strlcpy(err, lres.lrs_error, errlen);
				free(lres.lrs_error);
				return -1;
			}
		}
# endif /* _FFR_STATSEXT */

		str = NULL;
		(void) config_get(data, "FinalPolicyScript", &str, sizeof str);
		if (str != NULL)
		{
			int fd;
			ssize_t rlen;
			struct stat s;
			struct dkimf_lua_script_result lres;

			fd = open(str, O_RDONLY, 0);
			if (fd < 0)
			{
				snprintf(err, errlen, "%s: open(): %s", str,
				         strerror(errno));
				return -1;
			}

			if (fstat(fd, &s) == -1)
			{
				snprintf(err, errlen, "%s: fstat(): %s", str,
				         strerror(errno));
				close(fd);
				return -1;
			}

			conf->conf_finalscript = malloc(s.st_size + 1);
			if (conf->conf_finalscript == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				close(fd);
				return -1;
			}

			memset(conf->conf_finalscript, '\0', s.st_size + 1);
			rlen = read(fd, conf->conf_finalscript, s.st_size);
			if (rlen == -1)
			{
				snprintf(err, errlen, "%s: read(): %s",
				         str, strerror(errno));
				close(fd);
				return -1;
			}
			else if (rlen < s.st_size)
			{
				snprintf(err, errlen, "%s: early EOF",
				         str);
				close(fd);
				return -1;
			}

			close(fd);

			memset(&lres, '\0', sizeof lres);
			if (dkimf_lua_final_hook(NULL, conf->conf_finalscript,
			                         0, str, &lres,
			                         &conf->conf_finalfunc,
			                         &conf->conf_finalfuncsz) != 0)
			{
				strlcpy(err, lres.lrs_error, errlen);
				free(lres.lrs_error);
				return -1;
			}
		}
#endif /* USE_LUA */

		if (become == NULL)
		{
			(void) config_get(data, "Userid", &become,
			                  sizeof become);
		}
	}

#if defined(USE_LDAP) || defined(USE_ODBX)
	if (conf->conf_softstart)
		dbflags |= DKIMF_DB_FLAG_SOFTSTART;
#endif /* defined(USE_LDAP) || defined(USE_ODBX) */

	if (basedir[0] != '\0')
	{
		if (chdir(basedir) != 0)
		{
			snprintf(err, errlen, "%s: chdir(): %s",
			         basedir, strerror(errno));
			return -1;
		}
	}

	str = NULL;
	if (conf->conf_peerfile != NULL)
	{
		str = conf->conf_peerfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "PeerList", &str, sizeof str);
	}
	if (str != NULL && !testmode)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_peerdb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	if (conf->conf_testdnsdata != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_testdnsdb,
		                       conf->conf_testdnsdata,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	/* internal list */
	str = NULL;
	if (conf->conf_internalfile != NULL)
	{
		str = conf->conf_internalfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "InternalHosts", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_internal, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}
	else
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_internal, DEFINTERNAL,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         DEFINTERNAL, dberr);
			return -1;
		}
	}

	/* external ignore list */
	str = NULL;
	if (conf->conf_externalfile != NULL)
	{
		str = conf->conf_externalfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "ExternalIgnoreList", &str,
		                  sizeof str);
	}
	if (str != NULL && !testmode)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_exignore, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	/* exempt domains list */
	str = NULL;
	if (conf->conf_exemptfile != NULL)
	{
		str = conf->conf_exemptfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "ExemptDomains", &str, sizeof str);
	}
	if (str != NULL && !testmode)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_exemptdb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	/* BodyLengthDB */
	str = NULL;
	if (data != NULL)
		(void) config_get(data, "BodyLengthDB", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_bldb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "SignHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_signhdrsdb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "RemoveARFrom", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_remardb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

#ifdef _FFR_ATPS
	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "ATPSHashAlgorithm",
		                  &conf->conf_atpshash,
		                  sizeof conf->conf_atpshash);
		(void) config_get(data, "ATPSDomains", &str, sizeof str);
	}

	if (dkimf_lookup_strtoint(conf->conf_atpshash, dkimf_atpshash) != 1)
	{
		snprintf(err, errlen, "unknown ATPS hash \"%s\"",
		         conf->conf_atpshash);
		return -1;
	}

	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_atpsdb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}
#endif /* _FFR_ATPS */

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "DontSignMailTo", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_dontsigntodb, str,
		                       (dbflags | 
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "MustBeSigned", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_mbsdb, str,
		                       (dbflags |
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (conf->conf_omitlist != NULL)
	{
		str = conf->conf_omitlist;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "OmitHeaders", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_omithdrdb, str,
		                       (dbflags |
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "MTA", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_mtasdb, str,
		                       (dbflags | DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}

		status = dkimf_db_mkarray(conf->conf_mtasdb, &conf->conf_mtas,
		                          NULL);
		if (status == -1)
			return -1;
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "OverSignHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_oversigndb, str,
		                       (dbflags |
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "SenderHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_senderhdrsdb, str,
		                       (dbflags |
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}

		status = dkimf_db_mkarray(conf->conf_senderhdrsdb,
		                          &conf->conf_senderhdrs,
		                          NULL);
		if (status == -1)
			return -1;
	}

#ifdef _FFR_VBR
	if (data != NULL)
	{
		(void) config_get(data, "VBR-Type", &conf->conf_vbr_deftype,
		                  sizeof conf->conf_vbr_deftype);
		(void) config_get(data, "VBR-Certifiers",
		                  &conf->conf_vbr_defcert,
		                  sizeof conf->conf_vbr_defcert);
	}

	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "VBR-TrustedCertifiers", &str,
		                  sizeof str);
	}
	if (str != NULL)
	{
		char *dberr = NULL;
		int status;

		status = dkimf_db_open(&conf->conf_vbr_trusteddb, str,
		                       (dbflags |
		                        DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}

		(void) dkimf_db_mkarray(conf->conf_vbr_trusteddb,
		                        (char ***) &conf->conf_vbr_trusted,
		                        NULL);
	}

	if (data != NULL)
	{
		(void) config_get(data, "VBR-PurgeFields",
		                  &conf->conf_vbr_purge,
		                  sizeof conf->conf_vbr_purge);

		(void) config_get(data, "VBR-TrustedCertifiersOnly",
		                  &conf->conf_vbr_trustedonly,
		                  sizeof conf->conf_vbr_trustedonly);
	}
#endif /* _FFR_VBR */

	if (data != NULL)
	{
		(void) config_get(data, "SigningTable", &conf->conf_signtable,
		                  sizeof conf->conf_signtable);

		if (conf->conf_signtable != NULL)
		{
			int status;
			char *dberr = NULL;

			status = dkimf_db_open(&conf->conf_signtabledb,
			                       conf->conf_signtable,
			                       (dbflags |
			                        DKIMF_DB_FLAG_ICASE |
			                        DKIMF_DB_FLAG_ASCIIONLY |
			                        DKIMF_DB_FLAG_READONLY),
			                       NULL, &dberr);
			if (status != 0)
			{
				snprintf(err, errlen,
				         "%s: dkimf_db_open(): %s",
				         conf->conf_signtable, dberr);
				return -1;
			}
		}
	}

	if (data != NULL)
	{
		(void) config_get(data, "KeyTable", &conf->conf_keytable,
		                  sizeof conf->conf_keytable);

		if (conf->conf_keytable == NULL)
		{
			(void) config_get(data, "KeyFile", &conf->conf_keyfile,
			                  sizeof conf->conf_keyfile);
		}
		else
		{
			int status;
			char *dberr = NULL;

			status = dkimf_db_open(&conf->conf_keytabledb,
			                       conf->conf_keytable,
			                       (dbflags |
			                        DKIMF_DB_FLAG_READONLY), NULL,
			                       &dberr);
			if (status != 0)
			{
				snprintf(err, errlen,
				         "%s: dkimf_db_open(): %s",
				         conf->conf_keytable, dberr);
				return -1;
			}

			conf->conf_selector = NULL;
		}
	}

	if (conf->conf_signtabledb != NULL && conf->conf_keytabledb == NULL)
	{
		snprintf(err, errlen, "use of SigningTable requires KeyTable");
		return -1;
	}

	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "TrustSignaturesFrom", &str,
		                  sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_thirdpartydb, str,
		                       (dbflags | DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

#ifdef _FFR_RESIGN
	str = NULL;
	if (conf->conf_resign != NULL)
	{
		str = conf->conf_resign;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "ResignMailTo", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_resigndb, str,
		                       (dbflags | DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}
#endif /* _FFR_RESIGN */

#ifdef _FFR_RATE_LIMIT
	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "RateLimits", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_ratelimitdb, str,
		                       (dbflags | DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "FlowData", &str, sizeof str);

		(void) config_get(data, "FlowDataTTL", &conf->conf_flowdatattl,
		                  sizeof conf->conf_flowdatattl);

		(void) config_get(data, "FlowDataFactor",
		                  &conf->conf_flowfactor,
		                  sizeof conf->conf_flowfactor);
	}
	if (str != NULL)
	{
		int dbtype;
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_flowdatadb, str,
		                       (dbflags | DKIMF_DB_FLAG_ICASE |
		                        DKIMF_DB_FLAG_MAKELOCK),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}

		dbtype = dkimf_db_type(conf->conf_flowdatadb);
		if (dbtype != DKIMF_DB_TYPE_BDB)
		{
			snprintf(err, errlen,
			         "%s: invalid data set type for FlowData",
			         str);
			return -1;
		}
	}
#endif /* _FFR_RATE_LIMIT */

	str = NULL;
	if (conf->conf_domlist != NULL)
	{
		str = conf->conf_domlist;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "Domain", &str, sizeof str);
	}
	if (str != NULL && conf->conf_keytabledb == NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_domainsdb, str,
		                       (dbflags | DKIMF_DB_FLAG_READONLY |
		                        DKIMF_DB_FLAG_ICASE),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "MacroList", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		int dbtype;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_macrosdb, str,
		                       (dbflags | DKIMF_DB_FLAG_READONLY |
		                        DKIMF_DB_FLAG_VALLIST |
		                        DKIMF_DB_FLAG_MATCHBOTH), NULL,
		                       &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}

		dbtype = dkimf_db_type(conf->conf_macrosdb);
		if (dbtype != DKIMF_DB_TYPE_FILE &&
		    dbtype != DKIMF_DB_TYPE_CSL)
		{
			snprintf(err, errlen,
			         "%s: invalid data set type for MacroList",
			         str);
			return -1;
		}

		(void) dkimf_db_mkarray(conf->conf_macrosdb,
		                        &conf->conf_macros, NULL);
	}

	if (conf->conf_signalgstr != NULL)
	{
		conf->conf_signalg = dkimf_lookup_strtoint(conf->conf_signalgstr,
		                                           dkimf_sign);
		if (conf->conf_signalg == -1)
		{
			snprintf(err, errlen,
			         "unknown signing algorithm \"%s\"",
			         conf->conf_signalgstr);
			return -1;
		}
	}
	else
	{
		conf->conf_signalg = DKIM_SIGN_DEFAULT;
	}

	if (conf->conf_canonstr != NULL)
	{
		char *p;

		p = strchr(conf->conf_canonstr, '/');
		if (p == NULL)
		{
			conf->conf_hdrcanon = dkimf_lookup_strtoint(conf->conf_canonstr,
			                                            dkimf_canon);
			if (conf->conf_hdrcanon == -1)
			{
				snprintf(err, errlen,
				         "unknown canonicalization algorithm \"%s\"",
				         conf->conf_canonstr);
				return -1;
			}

			conf->conf_bodycanon = DKIM_CANON_DEFAULT;
		}
		else
		{
			*p = '\0';

			conf->conf_hdrcanon = dkimf_lookup_strtoint(conf->conf_canonstr,
			                                            dkimf_canon);
			if (conf->conf_hdrcanon == -1)
			{
				snprintf(err, errlen,
				         "unknown canonicalization algorithm \"%s\"",
				         conf->conf_canonstr);
				return -1;
			}

			conf->conf_bodycanon = dkimf_lookup_strtoint(p + 1,
			                                             dkimf_canon);
			if (conf->conf_bodycanon == -1)
			{
				snprintf(err, errlen,
				         "unknown canonicalization algorithm \"%s\"",
				         p + 1);
				return -1;
			}

			*p = '/';
		}
	}

	str = NULL;
	if (conf->conf_siglimit != NULL)
	{
		str = conf->conf_siglimit;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "Minimum", &str, sizeof str);
	}
	if (str != NULL)
	{
		unsigned long tmpl;
		char *p;

		errno = 0;

		if (str[0] == '-')
		{
			tmpl = ULONG_MAX;
			errno = ERANGE;
		}

		tmpl = strtoul(str, &p, 10);
		if (tmpl > UINT_MAX || errno != 0)
		{
			snprintf(err, errlen, "illegal value for \"Minimum\"");
			return -1;
		}

		conf->conf_sigmin = (unsigned int) tmpl;

		if (*p == '%')
		{
			if (conf->conf_sigmin > 100)
			{
				snprintf(err, errlen,
				         "illegal value for \"Minimum\"");
				return -1;
			}

			conf->conf_sigmintype = SIGMIN_PERCENT;
		}
		else if (*p == '+')
		{
			conf->conf_sigmintype = SIGMIN_MAXADD;
		}
		else if (*p != '\0')
		{
			snprintf(err, errlen, "illegal value for \"Minimum\"");
			return -1;
		}
	}

	maxsign = -1;
	if (data != NULL)
	{
		(void) config_get(data, "MaximumSignedBytes", &maxsign,
		                  sizeof maxsign);
	}
	if (maxsign != -1)
	{
		conf->conf_signbytes = (long) maxsign;
		conf->conf_blen = TRUE;
	}

	if (conf->conf_modestr == NULL)
	{
		conf->conf_mode = (testmode ? DKIMF_MODE_VERIFIER
		                            : DKIMF_MODE_DEFAULT);
	}
	else
	{
		char *p;

		conf->conf_mode = 0;

		for (p = conf->conf_modestr; *p != '\0'; p++)
		{
			switch (*p)
			{
			  case 's':
				conf->conf_mode |= DKIMF_MODE_SIGNER;
				break;

			  case 'v':
				conf->conf_mode |= DKIMF_MODE_VERIFIER;
				break;

			  default:
				snprintf(err, errlen, "unknown mode \"%c\"",
				         *p);
				return -1;
			}
		}
	}

#ifdef _FFR_REPLACE_RULES
	/* replacement list */
	str = NULL;
	if (data != NULL)
	{
		(void) config_get(data, "ReplaceHeaders", &str, sizeof str);
	}
	if (str != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_rephdrsdb, str,
		                       (dbflags | DKIMF_DB_FLAG_READONLY |
		                        DKIMF_DB_FLAG_ICASE), NULL,
		                       &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         str, dberr);
			return -1;
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "ReplaceRules", &str, sizeof str);
	if (str != NULL)
	{
		FILE *f;

		f = fopen(str, "r");
		if (f == NULL)
		{
			snprintf(err, errlen, "%s: fopen(): %s", str,
			         strerror(errno));
			return -1;
		}

		if (!dkimf_load_replist(f, &conf->conf_replist))
		{
			snprintf(err, errlen,
			         "failed to load ReplaceRules from %s", str);
			fclose(f);
			return -1;
		}

		fclose(f);
	}
#endif /* _FFR_REPLACE_RULES */

#ifdef _FFR_REPUTATION
	if (data != NULL)
	{
		(void) config_get(data, "ReputationTest",
		                  &conf->conf_reptest,
		                  sizeof conf->conf_reptest);

		(void) config_get(data, "ReputationVerbose",
		                  &conf->conf_repverbose,
		                  sizeof conf->conf_repverbose);

		(void) config_get(data, "ReputationLimits",
		                  &conf->conf_replimits,
		                  sizeof conf->conf_replimits);

		(void) config_get(data, "ReputationLimitModifiers",
		                  &conf->conf_replimitmods,
		                  sizeof conf->conf_replimitmods);

		(void) config_get(data, "ReputationCache",
		                  &conf->conf_repcache,
		                  sizeof conf->conf_repcache);

		(void) config_get(data, "ReputationCacheTTL",
		                  &conf->conf_repcachettl,
		                  sizeof conf->conf_repcachettl);

		(void) config_get(data, "ReputationDuplicates",
		                  &conf->conf_repdups,
		                  sizeof conf->conf_repdups);

		(void) config_get(data, "ReputationRatios",
		                  &conf->conf_repratios,
		                  sizeof conf->conf_repratios);

		(void) config_get(data, "ReputationLowTime",
		                  &conf->conf_replowtime,
		                  sizeof conf->conf_replowtime);

		(void) config_get(data, "ReputationTimeFactor",
		                  &conf->conf_repfactor,
		                  sizeof conf->conf_repfactor);

		(void) config_get(data, "ReputationTimeout",
		                  &conf->conf_reptimeout,
		                  sizeof conf->conf_reptimeout);

		(void) config_get(data, "ReputationSpamCheck",
		                  &conf->conf_repspamcheck,
		                  sizeof conf->conf_repspamcheck);

		(void) config_get(data, "ReputationMinimum",
		                  &conf->conf_repminimum,
		                  sizeof conf->conf_repminimum);
	}

	if (conf->conf_repspamcheck != NULL)
	{
		size_t tmplen;
		char tmpre[BUFRSZ + 1];

		tmplen = strlen(conf->conf_repspamcheck);
		if (tmplen < 3 ||
		    conf->conf_repspamcheck[0] != '/' ||
		    conf->conf_repspamcheck[tmplen - 1] != '/')
		{
			snprintf(err, errlen,
			         "invalid value for ReputationSpamCheck");
			return -1;
		}

		strlcpy(tmpre, conf->conf_repspamcheck + 1, sizeof tmpre);
		tmpre[tmplen - 2] = '\0';

		if (regcomp(&conf->conf_repspamre, tmpre, REG_EXTENDED) != 0)
		{
			snprintf(err, errlen,
			         "unusable value for ReputationSpamCheck");
			return -1;
		}
	}

	if (conf->conf_replowtime != NULL)
	{
		int status;
		char *dberr = NULL;

		status = dkimf_db_open(&conf->conf_replowtimedb,
		                       conf->conf_replowtime,
		                       (dbflags | DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         conf->conf_replowtime, dberr);
			return -1;
		}
	}

	if (conf->conf_repratios != NULL)
	{
		int status;
		char *dberr = NULL;

		if (conf->conf_replimits != NULL)
		{
			status = dkimf_db_open(&conf->conf_replimitsdb,
			                       conf->conf_replimits,
			                       (dbflags |
			                        DKIMF_DB_FLAG_READONLY), NULL,
			                       &dberr);
			if (status != 0)
			{
				snprintf(err, errlen,
				         "%s: dkimf_db_open(): %s",
				         conf->conf_replimits, dberr);
				return -1;
			}
		}

		if (conf->conf_replimitmods != NULL)
		{
			status = dkimf_db_open(&conf->conf_replimitmodsdb,
			                       conf->conf_replimitmods,
			                       (dbflags |
			                        DKIMF_DB_FLAG_READONLY), NULL,
			                       &dberr);
			if (status != 0)
			{
				snprintf(err, errlen,
				         "%s: dkimf_db_open(): %s",
				         conf->conf_replimitmods, dberr);
				return -1;
			}
		}

		status = dkimf_db_open(&conf->conf_repratiosdb,
		                       conf->conf_repratios,
		                       (dbflags | DKIMF_DB_FLAG_READONLY),
		                       NULL, &dberr);
		if (status != 0)
		{
			snprintf(err, errlen, "%s: dkimf_db_open(): %s",
			         conf->conf_repratios, dberr);
			return -1;
		}

		if (dkimf_rep_init(&conf->conf_rep, conf->conf_repfactor,
	                           conf->conf_repminimum,
	                           conf->conf_repcachettl,
	                           conf->conf_repcache,
	                           conf->conf_repdups,
	                           conf->conf_replimitsdb,
	                           conf->conf_replimitmodsdb,
	                           conf->conf_repratiosdb,
		                   conf->conf_replowtimedb) != 0)
		{
			snprintf(err, errlen,
			         "can't initialize reputation subsystem");
			return -1;
		}
	}
#endif /* _FFR_REPUTATION */

#ifdef _FFR_REPRRD
	if (data != NULL)
	{
		int hashdepth = REPRRD_DEFHASHDEPTH;
		char *root = NULL;

		(void) config_get(data, "ReputationTest",
		                  &conf->conf_reptest,
		                  sizeof conf->conf_reptest);
		(void) config_get(data, "ReputationVerbose",
		                  &conf->conf_repverbose,
		                  sizeof conf->conf_repverbose);

		(void) config_get(data, "ReputationRRDHashDepth",
		                  &hashdepth, sizeof hashdepth);
		(void) config_get(data, "ReputationRRDRoot",
		                  &root, sizeof root);

		if (hashdepth >= 0 && root != NULL)
		{
			conf->conf_reprrd = reprrd_init(root, hashdepth);
			if (conf->conf_reprrd == NULL)
			{
				snprintf(err, errlen,
				         "can't initialize reputation subsystem");
				return -1;
			}
		}
	}
#endif /* _FFR_REPRRD */

	dkimf_reportaddr(conf);

	/* load the secret key, if one was specified */
	if (conf->conf_keyfile != NULL)
	{
		int status;
		int fd;
		ssize_t rlen;
		ino_t ino;
		uid_t asuser = (uid_t) -1;
		u_char *s33krit;
		struct stat s;

		fd = open(conf->conf_keyfile, O_RDONLY, 0);
		if (fd < 0)
		{
			if (conf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "%s: open(): %s",
				       conf->conf_keyfile,
				       strerror(errno));

				errno = saveerrno;
			}

			snprintf(err, errlen, "%s: open(): %s",
			         conf->conf_keyfile, strerror(errno));
			return -1;
		}

		status = fstat(fd, &s);
		if (status != 0)
		{
			if (conf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "%s: stat(): %s",
				       conf->conf_keyfile,
				       strerror(errno));

				errno = saveerrno;
			}

			snprintf(err, errlen, "%s: stat(): %s",
			         conf->conf_keyfile, strerror(errno));
			close(fd);
			return -1;
		}
		else if (!S_ISREG(s.st_mode))
		{
			snprintf(err, errlen, "%s: open(): Not a regular file",
			         conf->conf_keyfile);
			close(fd);
			return -1;
		}

		if (become != NULL)
		{
			struct passwd *pw;
			char *p;
			char tmp[BUFRSZ + 1];

			strlcpy(tmp, become, sizeof tmp);

			p = strchr(tmp, ':');
			if (p != NULL)
				*p = '\0';

			pw = getpwnam(tmp);
			if (pw == NULL)
			{
				snprintf(err, errlen, "%s: no such user", tmp);
				close(fd);
				return -1;
			}

			asuser = pw->pw_uid;
		}

		if (!dkimf_securefile(conf->conf_keyfile, &ino, asuser,
		                      err, errlen) ||
		    (ino != (ino_t) -1 && ino != s.st_ino))
		{
			if (conf->conf_dolog)
			{
				int sev;

				sev = (conf->conf_safekeys ? LOG_ERR
				                           : LOG_WARNING);

				syslog(sev, "%s: key data is not secure: %s",
				       conf->conf_keyfile, err);
			}

			if (conf->conf_safekeys)
				return -1;
		}

		s33krit = malloc(s.st_size + 1);
		if (s33krit == NULL)
		{
			if (conf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "malloc(): %s", 
				       strerror(errno));

				errno = saveerrno;
			}

			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		conf->conf_keylen = s.st_size + 1;

		rlen = read(fd, s33krit, s.st_size + 1);
		if (rlen == (ssize_t) -1)
		{
			if (conf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "%s: read(): %s",
				       conf->conf_keyfile,
				       strerror(errno));

				errno = saveerrno;
			}

			snprintf(err, errlen, "%s: read(): %s",
			         conf->conf_keyfile, strerror(errno));
			close(fd);
			free(s33krit);
			return -1;
		}
		else if (rlen != s.st_size)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: read() wrong size (%lu)",
				       conf->conf_keyfile, (u_long) rlen);
			}

			snprintf(err, errlen, "%s: read() wrong size (%lu)",
			         conf->conf_keyfile, (u_long) rlen);
			close(fd);
			free(s33krit);
			return -1;
		}

		close(fd);
		s33krit[s.st_size] = '\0';
		conf->conf_seckey = s33krit;
	}

	/* confirm signing mode parameters */
	if ((conf->conf_mode & DKIMF_MODE_SIGNER) != 0)
	{
		if ((conf->conf_selector != NULL &&
		     conf->conf_keyfile == NULL) ||
		    (conf->conf_selector == NULL &&
		     conf->conf_keyfile != NULL))
		{
			snprintf(err, errlen,
			         "KeyFile and Selector must both be defined or both be undefined");
			return -1;
		}

		if (conf->conf_domainsdb != NULL &&
		    (conf->conf_selector == NULL ||
		     conf->conf_keyfile == NULL))
		{
			snprintf(err, errlen,
			         "Domain requires KeyFile and Selector");
			return -1;
		}

		if (conf->conf_signtable != NULL &&
		    conf->conf_keytable == NULL)
		{
			snprintf(err, errlen,
			         "SigningTable requires KeyTable");
			return -1;
		}

#ifdef USE_LUA
		if (conf->conf_keytable != NULL &&
		    conf->conf_signtable == NULL &&
		    conf->conf_setupscript == NULL)
		{
			snprintf(err, errlen,
			         "KeyTable requires either SigningTable or SetupPolicyScript");
			return -1;
		}
#else /* USE_LUA */
		if (conf->conf_keytable != NULL &&
		    conf->conf_signtable == NULL)
		{
			snprintf(err, errlen,
			         "KeyTable requires SigningTable");
			return -1;
		}
#endif /* USE_LUA */

		/*
		**  Verify that the SingingTable doesn't reference any
		**  missing KeyTable entries.
		*/

		if (conf->conf_signtabledb != NULL)
		{
			_Bool first = TRUE;
			_Bool found;
			struct dkimf_db_data dbd[3];
			char keyname[BUFRSZ + 1];
			char domain[BUFRSZ + 1];
			char selector[BUFRSZ + 1];
			char keydata[BUFRSZ + 1];
			char signer[BUFRSZ + 1];

			dbd[0].dbdata_flags = 0;
			
			memset(keyname, '\0', sizeof keyname);

			dbd[0].dbdata_buffer = keyname;
			dbd[0].dbdata_buflen = sizeof keyname - 1;
			dbd[0].dbdata_flags = 0;
			dbd[1].dbdata_buffer = signer;
			dbd[1].dbdata_buflen = sizeof signer - 1;
			dbd[1].dbdata_flags = 0;

			while (dkimf_db_walk(conf->conf_signtabledb, first,
			                     NULL, NULL, dbd, 2) == 0)
			{
				first = FALSE;
				found = FALSE;
				dbd[0].dbdata_buffer = domain;
				dbd[0].dbdata_buflen = sizeof domain - 1;
				dbd[0].dbdata_flags = 0;
				dbd[1].dbdata_buffer = selector;
				dbd[1].dbdata_buflen = sizeof selector - 1;
				dbd[1].dbdata_flags = 0;
				dbd[2].dbdata_buffer = keydata;
				dbd[2].dbdata_buflen = sizeof keydata - 1;
				dbd[2].dbdata_flags = DKIMF_DB_DATA_BINARY;

				if (dkimf_db_get(conf->conf_keytabledb,	
				                 keyname, strlen(keyname),
				                 dbd, 3, &found) != 0 ||
				    !found ||
				    dbd[0].dbdata_buflen == 0 ||
				    dbd[1].dbdata_buflen == 0 ||
				    dbd[2].dbdata_buflen == 0)
				{
					snprintf(err, errlen,
					         "could not find valid key record \"%s\" in KeyTable",
					         keyname);
					return -1;
				}

				memset(keyname, '\0', sizeof keyname);

				dbd[0].dbdata_buffer = keyname;
				dbd[0].dbdata_buflen = sizeof keyname - 1;
				dbd[0].dbdata_flags = 0;
			}
		}
	}

	/* activate logging if requested */
	if (conf->conf_dolog)
	{
		char *log_facility = NULL;

		if (data != NULL)
		{
			(void) config_get(data, "SyslogFacility", &log_facility,
			                  sizeof log_facility);
		}

		dkimf_init_syslog(log_facility);
	}

	return 0;
}

/*
**  DKIMF_DNS_INIT -- initialize and configure the DNS service in the
**                    DKIM library
**
**  Parameters:
**  	lib -- DKIM library
**  	conf -- configuration handle
**  	err -- error string (returned)
**
**  Return value:
**  	TRUE on success, FALSE otherwise
*/

static _Bool
dkimf_dns_init(DKIM_LIB *lib, struct dkimf_config *conf, char **err)
{
	int status;

	assert(lib != NULL);
	assert(conf != NULL);
	assert(err != NULL);

	status = dkim_dns_init(lib);
	if (status == DKIM_DNS_INVALID)
	{
		return TRUE;
	}
	else if (status == DKIM_DNS_ERROR)
	{
		if (err != NULL)
			*err = "failed to initialize resolver";

		return FALSE;
	}

	if (conf->conf_nslist != NULL)
	{
		status = dkimf_dns_setnameservers(lib,
						  conf->conf_nslist);
		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set nameserver list";
			return FALSE;
		}
	}

	if (conf->conf_trustanchorpath != NULL)
	{
		if (access(conf->conf_trustanchorpath, R_OK) != 0)
		{
			if (err != NULL)
				*err = "can't access unbound trust anchor";
			return FALSE;
		}

		status = dkimf_dns_trustanchor(lib,
					       conf->conf_trustanchorpath);
		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to add trust anchor";
			return FALSE;
		}
	}

	if (conf->conf_resolverconfig != NULL)
	{
		status = dkimf_dns_config(lib, conf->conf_resolverconfig);
		if (status != DKIM_DNS_SUCCESS)
		{
			if (err != NULL)
				*err = "failed to add resolver configuration file";
	
			return FALSE;
		}
	}

	return TRUE;
}

/*
**  DKIMF_CONFIG_SETLIB -- set library options based on configuration file
**
**  Parameters:
**  	conf -- DKIM filter configuration data
**  	err -- error string (returned; may be NULL)
**
**  Return value:
**  	TRUE on success, FALSE otherwise.
*/

static _Bool
dkimf_config_setlib(struct dkimf_config *conf, char **err)
{
	DKIM_STAT status;
	u_int opts;
	DKIM_LIB *lib;
	assert(conf != NULL);

	lib = conf->conf_libopendkim;
	if (lib == NULL)
	{
		lib = dkim_init(NULL, NULL);
		if (lib == NULL)
		{
			if (err != NULL)
				*err = "failed to initialize DKIM library";
			return FALSE;
		}

		conf->conf_libopendkim = lib;
	}

	(void) dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
	                    &opts, sizeof opts);
	opts |= (DKIM_LIBFLAGS_ACCEPTV05 | DKIM_LIBFLAGS_DROPSIGNER);
	if (conf->conf_weaksyntax)
		opts |= DKIM_LIBFLAGS_BADSIGHANDLES;
#ifdef QUERY_CACHE
	if (querycache)
	{
		opts |= DKIM_LIBFLAGS_CACHE;
		(void) time(&cache_lastlog);
	}
#endif /* QUERY_CACHE */
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &opts, sizeof opts);

	/* set the DNS callback */
	(void) dkim_set_dns_callback(lib, dkimf_sendprogress, CBINTERVAL);

	if (conf->conf_minkeybits != 0)
	{
		(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_MINKEYBITS,
		                    &conf->conf_minkeybits,
		                    sizeof conf->conf_minkeybits);
	}

	if (conf->conf_testdnsdb != NULL)
	{
		(void) dkimf_filedns_setup(lib, conf->conf_testdnsdb);
	}
	else
	{
#ifdef USE_UNBOUND
		(void) dkimf_unbound_setup(lib);
#endif /* USE_UNBOUND */

		if (!dkimf_dns_init(lib, conf, err))
			return FALSE;
		else
			dkim_dns_close(lib);
	}

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
	                    &conf->conf_dnstimeout,
	                    sizeof conf->conf_dnstimeout);

	if (conf->conf_clockdrift != 0)
	{
		uint64_t drift = conf->conf_clockdrift;

		status = dkim_options(lib, DKIM_OP_SETOPT,
		                      DKIM_OPTS_CLOCKDRIFT, &drift,
		                      sizeof drift);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM clock drift limit";
			return FALSE;
		}
	}

	if (conf->conf_sigttl != 0)
	{
		uint64_t sigtime = conf->conf_sigttl;

		status = dkim_options(lib, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNATURETTL, &sigtime,
		                      sizeof sigtime);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM signature TTL";
			return FALSE;
		}
	}

	if (conf->conf_sendreports || conf->conf_keeptmpfiles ||
	    conf->conf_stricthdrs || conf->conf_blen || conf->conf_ztags ||
	    conf->conf_fixcrlf)
	{
		u_int opts;

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_GETOPT,
		                      DKIM_OPTS_FLAGS, &opts, sizeof opts);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to retrieve DKIM library options";
			return FALSE;
		}

		if (conf->conf_sendreports || conf->conf_keeptmpfiles)
			opts |= DKIM_LIBFLAGS_TMPFILES;
		if (conf->conf_keeptmpfiles)
			opts |= DKIM_LIBFLAGS_KEEPFILES;
		if (conf->conf_blen)
			opts |= DKIM_LIBFLAGS_SIGNLEN;
		if (conf->conf_ztags)
			opts |= DKIM_LIBFLAGS_ZTAGS;
		if (conf->conf_fixcrlf)
			opts |= DKIM_LIBFLAGS_FIXCRLF;
		if (conf->conf_acceptdk)
			opts |= DKIM_LIBFLAGS_ACCEPTDK;
		if (conf->conf_stricthdrs)
			opts |= DKIM_LIBFLAGS_STRICTHDRS;

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_FLAGS, &opts, sizeof opts);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}

	if (conf->conf_oversigndb != NULL)
	{
		status = dkimf_db_mkarray(conf->conf_oversigndb,
		                          &conf->conf_oversignhdrs, NULL);
		if (status == -1)
		{
			if (err != NULL)
				*err = "failed to generate DB array";
			return FALSE;
		}

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_OVERSIGNHDRS,
		                      conf->conf_oversignhdrs,
		                      sizeof conf->conf_oversignhdrs);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}

	if (conf->conf_mbsdb != NULL)
	{
		status = dkimf_db_mkarray(conf->conf_mbsdb, &conf->conf_mbs,
		                          NULL);
		if (status == -1)
		{
			if (err != NULL)
				*err = "failed to generate DB array";
			return FALSE;
		}

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_MUSTBESIGNED,
		                      conf->conf_mbs, sizeof conf->conf_mbs);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}

	if (conf->conf_omithdrdb != NULL)
	{
		status = dkimf_db_mkarray(conf->conf_omithdrdb,
		                          &conf->conf_omithdrs,
		                          (const char **) dkim_should_not_signhdrs);
		if (status == -1)
		{
			if (err != NULL)
				*err = "failed to generate DB array";
			return FALSE;
		}

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SKIPHDRS,
		                      conf->conf_omithdrs,
		                      sizeof conf->conf_omithdrs);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}
	else
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SKIPHDRS,
		                      (void *) dkim_should_not_signhdrs,
		                      sizeof (u_char **));

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}

	if (conf->conf_signhdrsdb != NULL)
	{
		status = dkimf_db_mkarray(conf->conf_signhdrsdb,
		                          &conf->conf_signhdrs,
		                          (const char **) dkim_should_signhdrs);
		if (status == -1)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNHDRS, conf->conf_signhdrs,
		                      sizeof conf->conf_signhdrs);

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}
	else
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNHDRS,
		                      (void *) dkim_should_signhdrs,
		                      sizeof (u_char **));

		if (status != DKIM_STAT_OK)
		{
			if (err != NULL)
				*err = "failed to set DKIM library options";
			return FALSE;
		}
	}

	status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
	                      DKIM_OPTS_TMPDIR,
	                      (void *) conf->conf_tmpdir,
	                      sizeof conf->conf_tmpdir);

	if (status != DKIM_STAT_OK)
	{
		if (err != NULL)
			*err = "failed to set DKIM library options";
		return FALSE;
	}

	status = dkim_set_prescreen(conf->conf_libopendkim, dkimf_prescreen);
	if (status != DKIM_STAT_OK)
	{
		if (err != NULL)
			*err = "failed to set DKIM prescreen function";
		return FALSE;
	}

	return TRUE;
}

/*
**  DKIMF_CONFIG_RELOAD -- reload configuration if requested
**
**  Parameters:
**   	None.
**
**  Return value:
**  	None.
**
**  Side effects:
**  	If a reload was requested and is successful, "curconf" now points
**  	to a new configuration handle.
*/

static void
dkimf_config_reload(void)
{
	struct dkimf_config *new;
	char errbuf[BUFRSZ + 1];

	pthread_mutex_lock(&conf_lock);

	if (!reload)
	{
		pthread_mutex_unlock(&conf_lock);
		return;
	}

	if (conffile == NULL)
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "ignoring reload signal");

		reload = FALSE;

		pthread_mutex_unlock(&conf_lock);
		return;
	}

	new = dkimf_config_new();
	if (new == NULL)
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));
	}
	else
	{
		_Bool err = FALSE;
		u_int line;
		struct config *cfg;
		char *missing;
		char *errstr = NULL;
		char *deprecated = NULL;
		char path[MAXPATHLEN + 1];

		strlcpy(path, conffile, sizeof path);

		cfg = config_load(conffile, dkimf_config, &line,
		                  path, sizeof path, &deprecated);

		if (cfg == NULL)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: configuration error at line %u: %s",
				        path, line, config_error());
			}
			dkimf_config_free(new);
			err = TRUE;
		}

		if (deprecated != NULL)
		{
			char *action = "aborting";
			if (allowdeprecated)
				action = "continuing";

			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "%s: settings found for deprecated value(s): %s; %s",
				        path, deprecated, action);
			}

			if (!allowdeprecated)
			{
				dkimf_config_free(new);
				err = TRUE;
			}
		}

		if (!err)
		{
			missing = config_check(cfg, dkimf_config);
			if (missing != NULL)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					        "%s: required parameter \"%s\" missing",
					        conffile, missing);
				}
				config_free(cfg);
				dkimf_config_free(new);
				err = TRUE;
			}
		}

		if (!err && dkimf_config_load(cfg, new, errbuf,
		                              sizeof errbuf, NULL) != 0)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "%s: %s", conffile, errbuf);
			config_free(cfg);
			dkimf_config_free(new);
			err = TRUE;
		}

		if (!err && !dkimf_config_setlib(new, &errstr))
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "can't configure DKIM library: %s; continuing",
				       errstr);
			}
			config_free(cfg);
			dkimf_config_free(new);
			err = TRUE;
		}

		if (!err)
		{
			if (curconf->conf_refcnt == 0)
				dkimf_config_free(curconf);

			dolog = new->conf_dolog;
			curconf = new;
			new->conf_data = cfg;

			if (new->conf_dolog)
			{
				syslog(LOG_INFO,
				       "configuration reloaded from %s",
				       conffile);
			}
		}
	}

	reload = FALSE;

	pthread_mutex_unlock(&conf_lock);

	return;
}

/*
**  DKIMF_CHECKBLDB -- determine if an envelope recipient is one for which
**                     signing should be done with body length tags
**
**  Parameters:
**  	db -- DB handle
**  	to -- the recipient header
**  	jobid -- string of job ID for logging
**
**  Return value:
**  	TRUE iff the recipient email was found in the body length database.
*/

static _Bool
dkimf_checkbldb(DKIMF_DB db, char *to, char *jobid)
{
	int c;
	_Bool exists = FALSE;
	DKIM_STAT status;
	char *domain;
	char *user;
	char *p;
	char addr[MAXADDRESS + 1];
	char dbaddr[MAXADDRESS + 1];

	strlcpy(addr, to, sizeof addr);
	status = dkim_mail_parse(addr, (u_char **) &user, (u_char **) &domain);
	if (status != 0 || user == NULL || domain == NULL)
	{
		if (dolog)
		{
			syslog(LOG_INFO, "%s: can't parse %s: header",
			       jobid, to);
		}

		return FALSE;
	}

	for (p = domain; ; p = strchr(p + 1, '.'))
	{
		for (c = 0; c < 2; c++)
		{
			if (c == 1 && p == NULL)
			{
				dbaddr[0] = '*';
				dbaddr[1] = '\0';
			}
			else if (snprintf(dbaddr, sizeof dbaddr, "%s@%s",
			                  c == 0 ? user : "*",
			                  p == NULL ? "*" : p) >= (int) sizeof dbaddr)
			{
				if (dolog)
				{
					syslog(LOG_ERR,
					       "%s: overflow parsing \"%s\"",
					       jobid, to);
				}

				return FALSE;
			}

			status = dkimf_db_get(db, dbaddr, 0, NULL, 0, &exists);
			if (status == 0)
			{
				if (exists)
					return TRUE;
			}
			else if (dolog)
			{
				dkimf_db_error(db, dbaddr);
			}
		}

		if (p == NULL)
			break;
	}

	return FALSE;
}

/*
**  DKIMF_STDIO -- set up the base descriptors to go nowhere
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

static void
dkimf_stdio(void)
{
	int devnull;

	/* this only fails silently, but that's OK */
	devnull = open(_PATH_DEVNULL, O_RDWR, 0);
	if (devnull != -1)
	{
		(void) dup2(devnull, 0);
		(void) dup2(devnull, 1);
		(void) dup2(devnull, 2);
		if (devnull > 2)
			(void) close(devnull);
	}

	(void) setsid();
}

/*
**  DKIMF_SENDPROGRESS -- tell the MTA "we're working on it!"
**
**  Parameters:
**  	ctx -- context
**
**  Return value:
**  	None (yet).
*/

void
dkimf_sendprogress(const void *ctx)
{
	if (ctx != NULL)
	{
		struct connctx *cc;
		struct msgctx *dfc;

		cc = (struct connctx *) dkimf_getpriv((SMFICTX *) ctx);
		dfc = cc->cctx_msg;

		if (dfc->mctx_eom)
		{
			if (testmode)
				(void) dkimf_test_progress((SMFICTX *) ctx);
#ifdef HAVE_SMFI_PROGRESS
			else
				(void) smfi_progress((SMFICTX *) ctx);
#endif /* HAVE_SMFI_PROGRESS */
		}
	}
}

/*
**  DKIMF_INITCONTEXT -- initialize filter context
**
**  Parameters:
**  	conf -- pointer to the configuration for this connection
**
**  Return value:
**  	A pointer to an allocated and initialized filter context, or NULL
**  	on failure.
**
**  Side effects:
**  	Crop circles near Birmingham.
*/

static msgctx
dkimf_initcontext(struct dkimf_config *conf)
{
	msgctx ctx;

	assert(conf != NULL);

	ctx = (msgctx) malloc(sizeof(struct msgctx));
	if (ctx == NULL)
		return NULL;

	(void) memset(ctx, '\0', sizeof(struct msgctx));

	ctx->mctx_status = DKIMF_STATUS_UNKNOWN;
	ctx->mctx_hdrcanon = conf->conf_hdrcanon;
	ctx->mctx_bodycanon = conf->conf_bodycanon;
	ctx->mctx_signalg = DKIM_SIGN_DEFAULT;
	ctx->mctx_queryalg = DKIM_QUERY_DEFAULT;
#ifdef USE_UNBOUND
	ctx->mctx_dnssec_key = DKIM_DNSSEC_UNKNOWN;
#endif /* USE_UNBOUND */
#ifdef _FFR_ATPS
	ctx->mctx_atps = DKIM_ATPS_UNKNOWN;
#endif /* _FFR_ATPS */
#ifdef _FFR_REPUTATION
# ifdef USE_GNUTLS
	(void) gnutls_hash_init(&ctx->mctx_hash, GNUTLS_DIG_SHA1);
# else /* USE_GNUTLS */
	SHA1_Init(&ctx->mctx_hash);
# endif /* USE_GNUTLS */
#endif /* _FFR_REPUTATION */

	return ctx;
}

/*
**  DKIMF_LOG_SSL_ERRORS -- log any queued SSL library errors
**
**  Parameters:
**  	dkim -- DKIM handle
**  	sig -- signature handle
**  	jobid -- job ID to include in log messages
**
**  Return value:
**  	None.
*/

static void
dkimf_log_ssl_errors(DKIM *dkim, DKIM_SIGINFO *sig, char *jobid)
{
	char *selector;
	char *domain;
	const char *errbuf;

	assert(dkim != NULL);
	assert(jobid != NULL);

	if (sig != NULL)
	{
		domain = dkim_sig_getdomain(sig);
		selector = dkim_sig_getselector(sig);
		errbuf = dkim_sig_getsslbuf(sig);
	}
	else
	{
		domain = NULL;
		selector = NULL;
		errbuf = dkim_getsslbuf(dkim);
	}

	if (errbuf != NULL)
	{
		if (selector != NULL && domain != NULL)
		{
			syslog(LOG_INFO, "%s: s=%s d=%s SSL %s", jobid,
			       selector, domain, errbuf);
		}
		else
		{
			syslog(LOG_INFO, "%s: SSL %s", jobid, errbuf);
		}
	}
}

/*
**  DKIMF_CLEANUP -- release local resources related to a message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	None.
*/

static void
dkimf_cleanup(SMFICTX *ctx)
{
	msgctx dfc;
	connctx cc;

	assert(ctx != NULL);

	cc = (connctx) dkimf_getpriv(ctx);

	if (cc == NULL)
		return;

	dfc = cc->cctx_msg;

	/* release memory, reset state */
	if (dfc != NULL)
	{
		if (dfc->mctx_hqhead != NULL)
		{
			Header hdr;
			Header prev;

			hdr = dfc->mctx_hqhead;
			while (hdr != NULL)
			{
				TRYFREE(hdr->hdr_hdr);
				TRYFREE(hdr->hdr_val);
				prev = hdr;
				hdr = hdr->hdr_next;
				TRYFREE(prev);
			}
		}

		if (dfc->mctx_rcptlist != NULL)
		{
			struct addrlist *addr;
			struct addrlist *next;

			addr = dfc->mctx_rcptlist;
			while (addr != NULL)
			{
				next = addr->a_next;

				TRYFREE(addr->a_addr);
				TRYFREE(addr);

				addr = next;
			}
		}

		if (dfc->mctx_srhead != NULL)
		{
			struct signreq *sr;
			struct signreq *next;

			sr = dfc->mctx_srhead;
			while (sr != NULL)
			{
				next = sr->srq_next;

				if (sr->srq_dkim != NULL)
					dkim_free(sr->srq_dkim);
				TRYFREE(sr->srq_keydata);
				TRYFREE(sr->srq_domain);
				TRYFREE(sr->srq_selector);
				TRYFREE(sr->srq_signer);
				TRYFREE(sr);

				sr = next;
			}
		}

		if (dfc->mctx_dkimv != NULL)
			dkim_free(dfc->mctx_dkimv);

#ifdef _FFR_VBR
		if (dfc->mctx_vbr != NULL)
			vbr_close(dfc->mctx_vbr);

		TRYFREE(dfc->mctx_vbrinfo);
#endif /* _FFR_VBR */

		if (dfc->mctx_tmpstr != NULL)
			dkimf_dstring_free(dfc->mctx_tmpstr);

#ifdef _FFR_STATSEXT
		if (dfc->mctx_statsext != NULL)
		{
			struct statsext *cur;
			struct statsext *next;

			cur = dfc->mctx_statsext;
			while (cur != NULL)
			{
				next = cur->se_next;
	
				free(cur);

				cur = next;
			}
		}
#endif /* _FFR_STATSEXT */

#ifdef USE_LUA
		if (dfc->mctx_luaglobalh != NULL)
		{
			struct lua_global *cur;
			struct lua_global *next;

			cur = dfc->mctx_luaglobalh;
			while (cur != NULL)
			{
				next = cur->lg_next;

				if (cur->lg_type == LUA_TNUMBER ||
				    cur->lg_type == LUA_TSTRING)
					free(cur->lg_value);

				free(cur);

				cur = next;
			}
		}
#endif /* USE_LUA */

		free(dfc);
		cc->cctx_msg = NULL;
	}
}

/*
**  DKIMF_MILTERCODE -- apply an internal result code to libmilter
**
**  Parameters:
**  	ctx -- milter context
**  	dmc -- DKIMF_MILTER_* code
**  	str -- quarantine string (optional)
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
dkimf_miltercode(SMFICTX *ctx, int dmc, char *str)
{
	assert(ctx != NULL);

	switch (dmc)
	{
	  case DKIMF_MILTER_ACCEPT:
		return SMFIS_ACCEPT;

	  case DKIMF_MILTER_DISCARD:
		return SMFIS_DISCARD;

	  case DKIMF_MILTER_QUARANTINE:
		(void) dkimf_quarantine(ctx, str == NULL ? progname : str);
		return SMFIS_ACCEPT;

	  case DKIMF_MILTER_REJECT:
		return SMFIS_REJECT;

	  case DKIMF_MILTER_TEMPFAIL:
		return SMFIS_TEMPFAIL;
	}

	/* NOTREACHED */
	return SMFIS_ACCEPT;
}

/*
**  DKIMF_LIBSTATUS -- process a final status returned from libopendkim
**
**  Parameters:
**  	ctx -- milter context
**  	dkim -- DKIM handle producing the status
**  	where -- what function reported the error
**  	status -- status returned by a libdk call (DKIM_STAT_*)
**
**  Return value:
**   	An smfistat value to be returned to libmilter.
*/

static sfsistat
dkimf_libstatus(SMFICTX *ctx, DKIM *dkim, char *where, int status)
{
	int retcode = SMFIS_CONTINUE;
	msgctx dfc;
	connctx cc;
	DKIM_SIGINFO *sig;
	char *rcode = NULL;
	char *xcode = NULL;
	char *replytxt = NULL;
	struct dkimf_config *conf;
	u_char smtpprefix[BUFRSZ];

	assert(ctx != NULL);

	cc = dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	memset(smtpprefix, '\0', sizeof smtpprefix);

	switch (status)
	{
	  case DKIM_STAT_OK:
		retcode = SMFIS_CONTINUE;
		break;

	  case DKIM_STAT_INTERNAL:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_internal,
		                           NULL);
		if (conf->conf_capture)
			dfc->mctx_capture = TRUE;
		if (conf->conf_dolog)
		{
			const char *err = NULL;
			const char *sslerr = NULL;

			if (dkim != NULL)
				err = dkim_geterror(dkim);
			if (err == NULL)
				err = strerror(errno);
			sslerr = dkim_getsslbuf(dkim);

			syslog(LOG_ERR,
			       "%s: %s%sinternal error from libopendkim: %s%s%s",
			       JOBID(dfc->mctx_jobid),
			       where == NULL ? "" : where,
			       where == NULL ? "" : ": ", err,
			       sslerr == NULL ? "" : " ",
			       sslerr == NULL ? "" : sslerr);
		}
		replytxt = "internal DKIM error";
		break;

	  case DKIM_STAT_BADSIG:
		assert(dkim != NULL);
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_badsig,
		                           NULL);
		if (conf->conf_dolog)
		{
			syslog(LOG_NOTICE, "%s: bad signature data",
			       JOBID(dfc->mctx_jobid));
		}
		replytxt = "bad DKIM signature data";

		memset(smtpprefix, '\0', sizeof smtpprefix);
		sig = dkim_getsignature(dkim);
		(void) dkim_sig_getreportinfo(dkim, sig,
		                              NULL, 0,
		                              NULL, 0,
		                              NULL, 0,
		                              smtpprefix, sizeof smtpprefix,
		                              NULL);

		break;

	  case DKIM_STAT_NOSIG:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_nosig,
		                           NULL);
		if (conf->conf_dolog)
		{
			if (conf->conf_logwhy || retcode != SMFIS_ACCEPT)
			{
				syslog(retcode == SMFIS_ACCEPT ? LOG_DEBUG
				                               : LOG_NOTICE,
				       "%s: no signature data",
				       JOBID(dfc->mctx_jobid));
			}
		}
		replytxt = "no DKIM signature data";
		break;

	  case DKIM_STAT_NORESOURCE:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_internal,
		                           NULL);
		if (conf->conf_capture)
			dfc->mctx_capture = TRUE;
		if (conf->conf_dolog)
		{
			const char *err = NULL;

			if (dkim != NULL)
				err = dkim_geterror(dkim);
			if (err == NULL)
				err = strerror(errno);

			syslog(LOG_ERR, "%s: %s%sresource unavailable: %s",
			       JOBID(dfc->mctx_jobid),
			       where == NULL ? "" : where,
			       where == NULL ? "" : ": ", err);
		}
		replytxt = "resource unavailable";
		break;

	  case DKIM_STAT_CANTVRFY:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_badsig,
		                           NULL);
		if (conf->conf_dolog && dkim != NULL)
		{
			const char *err = NULL;
			err = dkim_geterror(dkim);
			if (err == NULL)
				err = "unknown cause";

			syslog(LOG_ERR, "%s: signature processing failed: %s",
				JOBID(dfc->mctx_jobid), err);
		}
		replytxt = "DKIM signature processing failed";
		break;

	  case DKIM_STAT_REVOKED:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_badsig,
		                           NULL);
		if (conf->conf_dolog)
		{
			u_char *selector = NULL;
			u_char *domain = NULL;
			DKIM_SIGINFO *sig;

			sig = dkim_getsignature(dkim);
			if (sig != NULL)
			{
				selector = dkim_sig_getselector(sig);
				domain = dkim_sig_getdomain(sig);
			}

			if (selector != NULL && domain != NULL)
			{
				syslog(LOG_NOTICE,
				       "%s: key revoked (s=%s, d=%s)",
				       JOBID(dfc->mctx_jobid), selector,
				       domain);
			}
		}
		break;

	  case DKIM_STAT_KEYFAIL:
	  case DKIM_STAT_NOKEY:
		if (status == DKIM_STAT_KEYFAIL)
		{
			retcode = dkimf_miltercode(ctx,
			                           conf->conf_handling.hndl_dnserr,
			                           NULL);
		}
		else
		{
			retcode = dkimf_miltercode(ctx,
			                           conf->conf_handling.hndl_nokey,
			                           NULL);
		}

		if (conf->conf_dolog)
		{
			const char *err = NULL;
			u_char *selector = NULL;
			u_char *domain = NULL;
			DKIM_SIGINFO *sig;

			err = dkim_geterror(dkim);

			sig = dkim_getsignature(dkim);
			if (sig != NULL)
			{
				selector = dkim_sig_getselector(sig);
				domain = dkim_sig_getdomain(sig);
			}

			if (selector != NULL && domain != NULL)
			{
				syslog(LOG_ERR,
				       "%s: key retrieval failed (s=%s, d=%s)%s%s",
				       JOBID(dfc->mctx_jobid), selector,
				       domain,
				       err == NULL ? "" : ": ",
				       err == NULL ? "" : err);
			}
			else
			{
				syslog(LOG_ERR, "%s: key retrieval failed%s%s",
				       JOBID(dfc->mctx_jobid),
				       err == NULL ? "" : ": ",
				       err == NULL ? "" : err);
			}
		}
		replytxt = "DKIM key retrieval failed";
		break;

	  case DKIM_STAT_SYNTAX:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_badsig,
		                           NULL);
		if (conf->conf_dolog)
		{
			const char *err = NULL;

			if (dkim != NULL)
				err = dkim_geterror(dkim);
			if (err == NULL)
				err = "unspecified";

			syslog(LOG_ERR, "%s: syntax error: %s",
			       JOBID(dfc->mctx_jobid), err);
		}
		replytxt = "DKIM signature syntax error";
		break;

	  case DKIM_STAT_SIGGEN:
		retcode = dkimf_miltercode(ctx,
		                           conf->conf_handling.hndl_siggen,
		                           NULL);

		if (conf->conf_dolog)
		{
			const char *err = NULL;

			if (dkim != NULL)
				err = dkim_geterror(dkim);
			if (err == NULL)
				err = "unspecified";

			syslog(LOG_ERR, "%s: signature generation error: %s",
			       JOBID(dfc->mctx_jobid), err);
		}

		replytxt = "DKIM signing error";
		break;
	}

	switch (retcode)
	{
	  case SMFIS_REJECT:
		rcode = "550";
		xcode = "5.7.0";
		break;

	  case SMFIS_TEMPFAIL:
		rcode = "451";
		if (status == DKIM_STAT_KEYFAIL || status == DKIM_STAT_NOKEY)
			xcode = "4.7.5";
		else
			xcode = "4.7.0";
		break;

	  default:
		break;
	}

	if (rcode != NULL && xcode != NULL && replytxt != NULL)
	{
		char replybuf[BUFRSZ];

		if (smtpprefix[0] == '\0')
		{
			strlcpy(replybuf, replytxt, sizeof replybuf);
		}
		else
		{
			snprintf(replybuf, sizeof replybuf, "%s: %s",
			         smtpprefix, replytxt);
		}

		(void) dkimf_setreply(ctx, rcode, xcode, replybuf);
	}

	return retcode;
}

/*
**  DKIMF_FINDHEADER -- find a header
**
**  Parameters:
**  	dfc -- filter context
**  	hname -- name of the header of interest
**  	instance -- which instance is wanted (0 = first)
**
**  Return value:
**  	Header handle, or NULL if not found.
**
**  Notes:
**  	Negative values of "instance" search backwards from the end.
*/

static Header
dkimf_findheader(msgctx dfc, char *hname, int instance)
{
	Header hdr;

	assert(dfc != NULL);
	assert(hname != NULL);

	if (instance < 0)
		hdr = dfc->mctx_hqtail;
	else
		hdr = dfc->mctx_hqhead;

	while (hdr != NULL)
	{
		if (strcasecmp(hdr->hdr_hdr, hname) == 0)
		{
			if (instance == 0 || instance == -1)
				return hdr;
			else if (instance > 0)
				instance--;
			else
				instance++;
		}

		if (instance < 0)
			hdr = hdr->hdr_prev;
		else
			hdr = hdr->hdr_next;
	}

	return NULL;
}

/*
**  DKIMF_APPLY_SIGNTABLE -- apply the signing table to a message
**
**  Parameters:
**  	dfc -- message context
**  	keydb -- database handle for key table
**  	signdb -- database handle for signing table
**  	user -- userid (local-part)
**  	domain -- domain
**  	errkey -- where to write the name of a key that failed
**  	errlen -- bytes available at "errkey"
**  	multisig -- apply multiple signature logic
**
**  Return value:
**  	>= 0 -- number of signatures added
** 	-1 -- signing table read error
**  	-2 -- unknown key
**  	-3 -- key load error
*/

static int
dkimf_apply_signtable(struct msgctx *dfc, DKIMF_DB keydb, DKIMF_DB signdb,
                      unsigned char *user, unsigned char *domain, char *errkey,
                      size_t errlen, _Bool multisig)
{
	_Bool found;
	int nfound = 0;
	char keyname[BUFRSZ + 1];
	u_char tmp[BUFRSZ + 1];

	assert(dfc != NULL);
	assert(keydb != NULL);
	assert(signdb != NULL);
	assert(user != NULL);
	assert(domain != NULL);

	if (dkimf_db_type(signdb) == DKIMF_DB_TYPE_REFILE)
	{
		int status;
		void *ctx = NULL;
		struct dkimf_db_data dbd[2];
		char addr[MAXADDRESS + 1];
		u_char signer[MAXADDRESS + 1];

		snprintf(addr, sizeof addr, "%s@%s", user, domain);

		memset(&dbd, '\0', sizeof dbd);
		dbd[0].dbdata_buffer = keyname;
		dbd[1].dbdata_buffer = (char *) signer;
		dbd[1].dbdata_flags = DKIMF_DB_DATA_OPTIONAL;

		/* walk RE set, find match(es), make request(s) */
		for (;;)
		{
			memset(keyname, '\0', sizeof keyname);
			dbd[0].dbdata_buflen = sizeof keyname - 1;
			memset(signer, '\0', sizeof signer);
			dbd[1].dbdata_buflen = sizeof signer - 1;

			status = dkimf_db_rewalk(signdb, addr, dbd, 2, &ctx);
			if (status == -1)
				return -1;
			else if (status == 1)
				break;

			if (keyname[0] == '%' && keyname[1] == '\0')
				strlcpy(keyname, domain, sizeof keyname);

			dkimf_reptoken(tmp, sizeof tmp, signer, domain);
			status = dkimf_add_signrequest(dfc, keydb, keyname,
			                               (char *) tmp,
			                               (ssize_t) -1);
			if (status != 0 && errkey != NULL)
				strlcpy(errkey, keyname, errlen);
			if (status == 1)
				return -2;
			else if (status == 2 || status == 3 || status == -1)
				return -3;

			nfound++;

			if (!multisig)
				return nfound;
		}
	}
	else
	{
		int status;
		char *p;
		char tmpaddr[MAXADDRESS + 1];
		u_char signer[MAXADDRESS + 1];
		struct dkimf_db_data req[2];

		memset(&req, '\0', sizeof req);

		memset(keyname, '\0', sizeof keyname);
		memset(signer, '\0', sizeof signer);
		req[0].dbdata_buffer = keyname;
		req[0].dbdata_buflen = sizeof keyname - 1;
		req[1].dbdata_buffer = (char *) signer;
		req[1].dbdata_buflen = sizeof signer - 1;
		req[1].dbdata_flags = DKIMF_DB_DATA_OPTIONAL;

		/* first try full "user@host" */
		snprintf(tmpaddr, sizeof tmpaddr, "%s@%s", user, domain);

		found = FALSE;
		status = dkimf_db_get(signdb, tmpaddr, strlen(tmpaddr),
		                      req, 2, &found);
		if (status != 0 ||
		    (found && (req[0].dbdata_buflen == 0 ||
		               req[0].dbdata_buflen == (size_t) -1)))
		{
			if (status != 0 && dolog)
				dkimf_db_error(signdb, tmpaddr);
			return -1;
		}
		else if (found)
		{
			if (keyname[0] == '%' && keyname[1] == '\0')
				strlcpy(keyname, domain, sizeof keyname);

			dkimf_reptoken(tmp, sizeof tmp, signer, domain);

			status = dkimf_add_signrequest(dfc, keydb, keyname,
			                               (char *) tmp,
			                               (ssize_t) -1);
			if (status != 0 && errkey != NULL)
				strlcpy(errkey, keyname, errlen);
			if (status == 1)
				return -2;
			else if (status == 2 || status == 3 || status == -1)
				return -3;

			nfound++;

			if (!multisig)
				return nfound;
		}

		/* now just "host" */
		found = FALSE;
		req[0].dbdata_buflen = sizeof keyname - 1;
		req[1].dbdata_buflen = sizeof signer - 1;
		memset(keyname, '\0', sizeof keyname);
		memset(signer, '\0', sizeof signer);
		status = dkimf_db_get(signdb, domain, strlen((char *) domain),
		                      req, 2, &found);
		if (status != 0 ||
		    (found && (req[0].dbdata_buflen == 0 ||
		               req[0].dbdata_buflen == (size_t) -1)))
		{
			if (status != 0 && dolog)
				dkimf_db_error(signdb, (char *) domain);
			return -1;
		}
		else if (found)
		{
			if (keyname[0] == '%' && keyname[1] == '\0')
				strlcpy(keyname, domain, sizeof keyname);

			dkimf_reptoken(tmp, sizeof tmp, signer, domain);

			status = dkimf_add_signrequest(dfc, keydb, keyname,
			                               (char *) tmp,
			                               (ssize_t) -1);
			if (status != 0 && errkey != NULL)
				strlcpy(errkey, keyname, errlen);
			if (status == 1)
				return -2;
			else if (status == 2 || status == 3 || status == -1)
				return -3;

			nfound++;

			if (!multisig)
				return nfound;
		}

		/* next "user@.domain" and ".domain", degrading */
		for (p = strchr((char *) domain, '.');
		     p != NULL;
		     p = strchr(p + 1, '.'))
		{
			snprintf(tmpaddr, sizeof tmpaddr, "%s@%s",
			         user, p);

			found = FALSE;
			req[0].dbdata_buflen = sizeof keyname - 1;
			req[1].dbdata_buflen = sizeof signer - 1;
			memset(keyname, '\0', sizeof keyname);
			memset(signer, '\0', sizeof signer);
			status = dkimf_db_get(signdb, tmpaddr, strlen(tmpaddr),
			                      req, 2, &found);
			if (status != 0 ||
			    (found && (req[0].dbdata_buflen == 0 ||
			               req[0].dbdata_buflen == (size_t) -1)))
			{
				if (status != 0 && dolog)
					dkimf_db_error(signdb, tmpaddr);
				return -1;
			}
			else if (found)
			{
				if (keyname[0] == '%' && keyname[1] == '\0')
				{
					strlcpy(keyname, domain,
					        sizeof keyname);
				}

				dkimf_reptoken(tmp, sizeof tmp, signer,
				               domain);

				status = dkimf_add_signrequest(dfc, keydb,
				                               keyname,
				                               (char *) tmp,
				                               (ssize_t) -1);
				if (status != 0 && errkey != NULL)
					strlcpy(errkey, keyname, errlen);
				if (status == 1)
					return -2;
				else if (status == 2 || status == 3 ||
				         status == -1)
					return -3;

				nfound++;

				if (!multisig)
					return nfound;
			}

			found = FALSE;
			req[0].dbdata_buflen = sizeof keyname - 1;
			req[1].dbdata_buflen = sizeof signer - 1;
			memset(keyname, '\0', sizeof keyname);
			memset(signer, '\0', sizeof signer);
			status = dkimf_db_get(signdb, p, strlen(p),
			                      req, 2, &found);
			if (status != 0 ||
			    (found && (req[0].dbdata_buflen == 0 ||
			               req[0].dbdata_buflen == (size_t) -1)))
			{
				if (status != 0 && dolog)
					dkimf_db_error(signdb, p);
				return -1;
			}
			else if (found)
			{
				if (keyname[0] == '%' && keyname[1] == '\0')
				{
					strlcpy(keyname, domain,
					        sizeof keyname);
				}

				dkimf_reptoken(tmp, sizeof tmp, signer,
				               domain);

				status = dkimf_add_signrequest(dfc, keydb,
				                               keyname,
				                               (char *) tmp,
				                               (ssize_t) -1);
				if (status != 0 && errkey != NULL)
					strlcpy(errkey, keyname, errlen);
				if (status == 1)
					return -2;
				else if (status == 2 || status == 3 ||
				         status == -1)
					return -3;

				nfound++;

				if (!multisig)
					return nfound;
			}
		}

		/* now "user@*" */
		snprintf(tmpaddr, sizeof tmpaddr, "%s@*", user);

		found = FALSE;
		req[0].dbdata_buflen = sizeof keyname - 1;
		req[1].dbdata_buflen = sizeof signer - 1;
		memset(keyname, '\0', sizeof keyname);
		memset(signer, '\0', sizeof signer);
		status = dkimf_db_get(signdb, tmpaddr, strlen(tmpaddr),
		                      req, 2, &found);
		if (status != 0 ||
		    (found && (req[0].dbdata_buflen == 0 ||
		               req[0].dbdata_buflen == (size_t) -1)))
		{
			if (status != 0 && dolog)
				dkimf_db_error(signdb, tmpaddr);
			return -1;
		}
		else if (found)
		{
			if (keyname[0] == '%' && keyname[1] == '\0')
				strlcpy(keyname, domain, sizeof keyname);

			dkimf_reptoken(tmp, sizeof tmp, signer, domain);

			status = dkimf_add_signrequest(dfc, keydb, keyname,
			                               (char *) tmp,
			                               (ssize_t) -1);
			if (status != 0 && errkey != NULL)
				strlcpy(errkey, keyname, errlen);
			if (status == 1)
				return -2;
			else if (status == 2 || status == 3 || status == -1)
				return -3;

			nfound++;

			if (!multisig)
				return nfound;
		}

		/* finally just "*" */
		found = FALSE;
		req[0].dbdata_buflen = sizeof keyname - 1;
		req[1].dbdata_buflen = sizeof signer - 1;
		memset(keyname, '\0', sizeof keyname);
		memset(signer, '\0', sizeof signer);
		status = dkimf_db_get(signdb, "*", 1, req, 2, &found);
		if (status != 0 ||
		    (found && (req[0].dbdata_buflen == 0 ||
		               req[0].dbdata_buflen == (size_t) -1)))
		{
			if (status != 0 && dolog)
				dkimf_db_error(signdb, "*");
			return -1;
		}
		else if (found)
		{
			if (keyname[0] == '%' && keyname[1] == '\0')
				strlcpy(keyname, domain, sizeof keyname);

			dkimf_reptoken(tmp, sizeof tmp, signer, domain);

			status = dkimf_add_signrequest(dfc, keydb, keyname,
			                               (char *) tmp,
			                               (ssize_t) -1);
			if (status != 0 && errkey != NULL)
				strlcpy(errkey, keyname, errlen);
			if (status == 1)
				return -2;
			else if (status == 2 || status == 3 || status == -1)
				return -3;

			nfound++;

			if (!multisig)
				return nfound;
		}
	}

	return nfound;
}

/*
**  DKIMF_SIGREPORT -- generate a report on signature failure (if possible)
**
**  Parameters:
**   	cc -- connection context
**  	conf -- current configuration object
**  	hostname -- hostname to use for reporting MTA
**
**  Return value:
**  	None.
*/

static void
dkimf_sigreport(connctx cc, struct dkimf_config *conf, char *hostname)
{
	_Bool sendreport = FALSE;
	int bfd = -1;
	int hfd = -1;
	int status;
	int arftype = ARF_TYPE_UNKNOWN;
	int arfdkim = ARF_DKIMF_UNKNOWN;
	u_int pct = 100;
	u_int rn;
	time_t now;
	DKIM_STAT repstatus;
	char *p;
	char *last;
	FILE *out;
	msgctx dfc;
	DKIM_SIGINFO *sig;
	struct Header *hdr;
	struct tm tm;
	char ipstr[DKIM_MAXHOSTNAMELEN + 1];
	char opts[BUFRSZ];
	char fmt[BUFRSZ];
	u_char addr[MAXADDRESS + 1];

	assert(cc != NULL);

	dfc = cc->cctx_msg;

	assert(dfc->mctx_dkimv != NULL);
	assert(conf != NULL);
	assert(hostname != NULL);

	memset(addr, '\0', sizeof addr);
	memset(opts, '\0', sizeof opts);

	sig = dkim_getsignature(dfc->mctx_dkimv);

	/* if no report is possible, just skip it */
	repstatus = dkim_sig_getreportinfo(dfc->mctx_dkimv, sig,
	                                   &hfd, &bfd,
	                                   (u_char *) addr, sizeof addr,
	                                   (u_char *) opts, sizeof opts,
	                                   NULL, 0, &pct);
	if (repstatus != DKIM_STAT_OK || addr[0] == '\0')
		return;

	if (pct < 100)
	{
		rn = random() % 100;
		if (rn > pct)
			return;
	}

	/* ignore any domain name in "r=" */
	p = strchr((char *) addr, '@');
	if (p != NULL)
		*p = '\0';

	/* ensure the event being reported was requested */
	if (opts[0] == '\0')
	{
		sendreport = TRUE;
	}
	else
	{
		for (p = strtok_r(opts, ":", &last);
		     p != NULL;
		     p = strtok_r(NULL, ":", &last))
		{
			if (strcasecmp(p, ARF_OPTIONS_DKIM_ALL) == 0)
			{
				sendreport = TRUE;
				break;
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_SYNTAX) == 0)
			{
				int err;

				err = dkim_sig_geterror(sig);

				if (err == DKIM_SIGERROR_TIMESTAMPS ||
				    err == DKIM_SIGERROR_INVALID_HC ||
				    err == DKIM_SIGERROR_INVALID_BC ||
				    err == DKIM_SIGERROR_MISSING_A ||
				    err == DKIM_SIGERROR_INVALID_A ||
				    err == DKIM_SIGERROR_MISSING_H ||
				    err == DKIM_SIGERROR_INVALID_L ||
				    err == DKIM_SIGERROR_INVALID_Q ||
				    err == DKIM_SIGERROR_INVALID_QO ||
				    err == DKIM_SIGERROR_MISSING_D ||
				    err == DKIM_SIGERROR_EMPTY_D ||
				    err == DKIM_SIGERROR_MISSING_S ||
				    err == DKIM_SIGERROR_EMPTY_S ||
				    err == DKIM_SIGERROR_MISSING_B ||
				    err == DKIM_SIGERROR_EMPTY_B ||
				    err == DKIM_SIGERROR_CORRUPT_B ||
				    err == DKIM_SIGERROR_MISSING_BH ||
				    err == DKIM_SIGERROR_EMPTY_BH ||
				    err == DKIM_SIGERROR_CORRUPT_BH ||
				    err == DKIM_SIGERROR_EMPTY_H ||
				    err == DKIM_SIGERROR_INVALID_H ||
				    err == DKIM_SIGERROR_TOOLARGE_L ||
				    err == DKIM_SIGERROR_MISSING_V ||
				    err == DKIM_SIGERROR_EMPTY_V)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_EXPIRED) == 0)
			{
				if (dkim_sig_geterror(sig) == DKIM_SIGERROR_EXPIRED)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_VERIFY) == 0)
			{
				if (dkim_sig_geterror(sig) == DKIM_SIGERROR_BADSIG ||
				    dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_DNS) == 0)
			{
				int err;

				err = dkim_sig_geterror(sig);

				if (err == DKIM_SIGERROR_NOKEY ||
				    err == DKIM_SIGERROR_DNSSYNTAX ||
				    err == DKIM_SIGERROR_KEYFAIL ||
				    err == DKIM_SIGERROR_KEYDECODE ||
				    err == DKIM_SIGERROR_MULTIREPLY)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_POLICY) == 0)
			{
				int err;

				err = dkim_sig_geterror(sig);

				if (err == DKIM_SIGERROR_MBSFAILED)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_DKIM_OTHER) == 0)
			{
				int err;

				err = dkim_sig_geterror(sig);

				if (err == DKIM_SIGERROR_SUBDOMAIN ||
				    err == DKIM_SIGERROR_KEYVERSION ||
				    err == DKIM_SIGERROR_KEYUNKNOWNHASH ||
				    err == DKIM_SIGERROR_KEYHASHMISMATCH ||
				    err == DKIM_SIGERROR_NOTEMAILKEY ||
				    err == DKIM_SIGERROR_KEYTYPEMISSING ||
				    err == DKIM_SIGERROR_KEYTYPEUNKNOWN ||
				    err == DKIM_SIGERROR_KEYREVOKED)
				{
					sendreport = TRUE;
					break;
				}
			}
		}
	}

	if (!sendreport)
		return;

#ifdef HAVE_CURL_EASY_STRERROR
	if (conf->conf_smtpuri != NULL)
	{
		int fd;
		char path[MAXPATHLEN + 1];

		snprintf(path, sizeof path, "%s/%s.XXXXXX", conf->conf_tmpdir,
		         progname);

		fd = mkstemp(path);
		if (fd < 0)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: mkstemp(): %s",
				       dfc->mctx_jobid, strerror(errno));
			}

			return;
		}

		unlink(path);

		out = fdopen(fd, "w");
		if (out == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: fdopen(): %s",
				       dfc->mctx_jobid, strerror(errno));
			}
	
			close(fd);
			return;
		}
	}
	else
	{
		out = popen(reportcmd, "w");
		if (out == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: popen(): %s",
				       dfc->mctx_jobid, strerror(errno));
			}
	
			return;
		}
	}
#else /* HAVE_CURL_EASY_STRERROR */
	out = popen(reportcmd, "w");
	if (out == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: popen(): %s",
			       dfc->mctx_jobid, strerror(errno));
		}

		return;
	}
#endif /* HAVE_CURL_EASY_STRERROR */

	/* determine the type of ARF failure and, if needed, a DKIM fail code */
	arftype = dkimf_arftype(dfc);
	if (arftype == ARF_TYPE_AUTHFAIL)
		arfdkim = dkimf_arfdkim(dfc);

	/* From: */
	fprintf(out, "From: %s\n", reportaddr);

	/* To: */
	fprintf(out, "To: %s@%s\n", addr, dkim_sig_getdomain(sig));

	/* Bcc: */
	if (conf->conf_reportaddrbcc != NULL)
		fprintf(out, "Bcc: %s\n", conf->conf_reportaddrbcc);

	/* Date: */
	memset(fmt, '\0', sizeof fmt);
	(void) time(&now);
	(void) localtime_r(&now, &tm);
	(void) strftime(fmt, sizeof fmt, "%a, %e %b %Y %H:%M:%S %z (%Z)", &tm);
	fprintf(out, "Date: %s\n", fmt);

	/* Subject: */
	fprintf(out, "Subject: DKIM failure report for %s\n",
	        dfc->mctx_jobid);

	/* MIME stuff */
	fprintf(out, "MIME-Version: 1.0\n");
	fprintf(out,
	        "Content-Type: multipart/report; report-type=feedback-report;\n\tboundary=\"dkimreport/%s/%s\"",
	        hostname, dfc->mctx_jobid);

	/* ok, now then... */
	fprintf(out, "\n");

	/* first part: a text blob explaining what this is */
	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: text/plain\n");
	fprintf(out, "\n");
	fprintf(out, "DKIM failure report for job %s on %s\n\n",
	        dfc->mctx_jobid, hostname);
	fprintf(out,
	        "The canonicalized form of the failed message's header and body are\nattached.\n");
	fprintf(out, "\n");

	/* second part: formatted gunk */
	memset(ipstr, '\0', sizeof ipstr);

	switch (cc->cctx_ip.ss_family)
	{
	  case AF_INET:
	  {
		struct sockaddr_in sin4;

		memcpy(&sin4, &cc->cctx_ip, sizeof sin4);

		(void) inet_ntop(AF_INET, &sin4.sin_addr, ipstr, sizeof ipstr);

		break;
	  }

#ifdef AF_INET6
	  case AF_INET6:
	  {
		struct sockaddr_in6 sin6;

		memcpy(&sin6, &cc->cctx_ip, sizeof sin6);

		(void) inet_ntop(AF_INET6, &sin6.sin6_addr, ipstr, sizeof ipstr);

		break;
	  }
#endif /* AF_INET6 */
	}

	hdr = dkimf_findheader(dfc, (char *) "Message-ID", 0);

	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: message/feedback-report\n");
	fprintf(out, "\n");
	fprintf(out, "User-Agent: %s/%s\n", DKIMF_PRODUCTNS, VERSION);
	fprintf(out, "Version: %s\n", ARF_VERSION);
	fprintf(out, "Original-Envelope-Id: %s\n", dfc->mctx_jobid);
	fprintf(out, "Original-Mail-From: %s\n", dfc->mctx_envfrom);
	fprintf(out, "Reporting-MTA: %s\n", hostname);
	fprintf(out, "Source-IP: %s\n", ipstr);
	fprintf(out, "Message-ID:%s%s\n",
	        cc->cctx_noleadspc ? "" : " ",
	        hdr == NULL ? "(none)" : hdr->hdr_val);
	fprintf(out, "Arrival-Date: %s\n", fmt);
	fprintf(out, "Reported-Domain: %s\n", dkim_sig_getdomain(sig));
	fprintf(out, "Delivery-Result: other\n");
	fprintf(out, "Feedback-Type: %s\n", arf_type_string(arftype));
	if (arftype == ARF_TYPE_AUTHFAIL)
	{
		fprintf(out, "Auth-Failure: ");
		if (dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
		{
			fprintf(out, "bodyhash\n");
		}
		else
		{
			const char *tmperror;

			switch (dkim_sig_geterror(sig))
			{
			  case DKIM_SIGERROR_KEYREVOKED:
				fprintf(out, "revoked\n");
				break;

			  default:
				tmperror = dkim_sig_geterrorstr(dkim_sig_geterror(sig));
				fprintf(out, "signature");
				if (tmperror != NULL)
					fprintf(out, " (%s)", tmperror);
				fprintf(out, "\n");
				break;
			}
		}

		memset(addr, '\0', sizeof addr);
		dkim_sig_getidentity(dfc->mctx_dkimv, sig, addr,
		                     sizeof addr - 1);

		/* fprintf(out, "Authentication-Results: %s\n", ...); */
		fprintf(out, "DKIM-Failure: %s\n",
		        arf_dkim_failure_string(arfdkim));
		fprintf(out, "DKIM-Domain: %s\n", dkim_sig_getdomain(sig));
		fprintf(out, "DKIM-Selector: %s\n", dkim_sig_getselector(sig));
		fprintf(out, "DKIM-Identity: %s\n", addr);
		if (hfd != -1)
		{
			fprintf(out, "DKIM-Canonicalized-Header: ");
			(void) dkimf_base64_encode_file(hfd, out, 4, 75, 27);
			fprintf(out, "\n");
		}
		if (bfd != -1)
		{
			fprintf(out, "DKIM-Canonicalized-Body: ");
			(void) dkimf_base64_encode_file(bfd, out, 4, 75, 25);
			fprintf(out, "\n");
		}
	}

	fprintf(out, "\n");

	/* third part: header block */
	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: text/rfc822-headers\n");
	fprintf(out, "\n");

	for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		fprintf(out, "%s:%s%s\n", hdr->hdr_hdr,
		        cc->cctx_noleadspc ? "" : " ", hdr->hdr_val);
	}

	/* end */
	fprintf(out, "\n--dkimreport/%s/%s--\n", hostname, dfc->mctx_jobid);

	/* send it */
#ifdef HAVE_CURL_EASY_SETOPT
	if (conf->conf_smtpuri != NULL)
	{
		CURLcode cc;
		CURL *curl;
		struct curl_slist *rcpts = NULL;
		char dest[MAXADDRESS + 1];

		(void) fseek(out, SEEK_SET, 0);

		curl = curl_easy_init();
		if (curl == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: curl_easy_init() failed",
				       dfc->mctx_jobid);
			}
		}
		else
		{
			cc = curl_easy_setopt(curl, CURLOPT_URL,
			                      conf->conf_smtpuri);

			if (cc == CURLE_OK)
			{
				cc = curl_easy_setopt(curl, CURLOPT_READDATA,
				                      out);
			}

			if (cc == CURLE_OK)
			{
				cc = curl_easy_setopt(curl, CURLOPT_MAIL_FROM,
				                      reportaddr);
			}

			if (cc == CURLE_OK)
			{
				snprintf(dest, sizeof dest, "%s@%s", addr,
				         dkim_sig_getdomain(sig));
				rcpts = curl_slist_append(rcpts, dest);
				cc = curl_easy_setopt(curl, CURLOPT_MAIL_RCPT,
				                      rcpts);
			}

			if (cc != CURLE_OK)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: curl_easy_setopt() failed",
					       dfc->mctx_jobid);
				}
			}
			else
			{
				cc = curl_easy_perform(curl);
				if (cc != CURLE_OK && conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: curl_easy_perform() to %s failed: %s",
					       dfc->mctx_jobid, dest,
					       curl_easy_strerror(cc));
				}
			}

			curl_slist_free_all(rcpts);

			curl_easy_cleanup(curl);
		}
	}
	else
	{
		status = pclose(out);
		if (status != 0 && conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: pclose(): returned status %d",
			       dfc->mctx_jobid, status);
		}
	}
#else /* HAVE_CURL_EASY_SETOPT */
	status = pclose(out);
	if (status != 0 && conf->conf_dolog)
	{
		syslog(LOG_ERR, "%s: pclose(): returned status %d",
		       dfc->mctx_jobid, status);
	}
#endif /* HAVE_CURL_EASY_SETOPT */
}

/*
**  DKIMF_AR_ALL_SIGS -- append Authentication-Results items for all signatures
**
**  Parameters:
**  	hdr -- header buffer
** 	hdrlen -- size of header buffer
**  	dkim -- DKIM verification handle
**  	conf -- config object
**  	status -- message context status (may be updated)
**
**  Return value:
**  	FALSE iff the filter should reject the message based on results.
*/

void
dkimf_ar_all_sigs(char *hdr, size_t hdrlen, DKIM *dkim,
                  struct dkimf_config *conf, int *status)
{
	int nsigs;
	DKIM_STAT dstatus;
	DKIM_SIGINFO **sigs;

	assert(hdr != NULL);
	assert(dkim != NULL);
	assert(conf != NULL);
	assert(status != NULL);

	dstatus = dkim_getsiglist(dkim, &sigs, &nsigs);
	if (dstatus == DKIM_STAT_OK)
	{
		int c;
		int sigerror;
		DKIM_STAT ts;
		u_int keybits;
		size_t ssl;
		char *result;
		char *dnssec;
		char *domain;
		char ss[BUFRSZ + 1];
		char tmp[BUFRSZ + 1];
		char val[MAXADDRESS + 1];
		char comment[BUFRSZ + 1];

		for (c = 0; c < nsigs; c++)
		{
			dnssec = NULL;

			memset(comment, '\0', sizeof comment);

			sigerror = dkim_sig_geterror(sigs[c]);

			if (dkim_sig_getkeysize(sigs[c],
			                        &keybits) != DKIM_STAT_OK)
				keybits = 0;

			ssl = sizeof ss - 1;
			ts = dkim_get_sigsubstring(dkim, sigs[c], ss, &ssl);

			if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) != 0 &&
			    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH)
			{
				result = "pass";
			}
			else if (sigerror == DKIM_SIGERROR_MULTIREPLY ||
			         sigerror == DKIM_SIGERROR_KEYFAIL ||
			         sigerror == DKIM_SIGERROR_DNSSYNTAX)
			{
				result = "temperror";
			}
			else if (sigerror == DKIM_SIGERROR_KEYTOOSMALL)
			{
				const char *err;

				result = "policy";

				err = dkim_sig_geterrorstr(dkim_sig_geterror(sigs[c]));
				if (err != NULL)
				{
					snprintf(comment, sizeof comment,
					         " reason=\"%s\"", err);
				}
			}
			else if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PROCESSED) != 0 &&
			         ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 ||
			          dkim_sig_getbh(sigs[c]) != DKIM_SIGBH_MATCH))
			{
				const char *err;

				result = "fail";

				err = dkim_sig_geterrorstr(dkim_sig_geterror(sigs[c]));
				if (err != NULL)
				{
					snprintf(comment, sizeof comment,
					         " reason=\"%s\"", err);
				}
			}
			else if (sigerror != DKIM_SIGERROR_UNKNOWN &&
			         sigerror != DKIM_SIGERROR_OK)
			{
				result = "permerror";
			}
			else
			{
				result = "neutral";
			}

			dnssec = NULL;

#ifdef USE_UNBOUND
			switch (dkim_sig_getdnssec(sigs[c]))
			{
			  case DKIM_DNSSEC_UNKNOWN:
				break;

			  case DKIM_DNSSEC_INSECURE:
				dnssec = "unprotected";
				if (conf->conf_unprotectedkey == DKIMF_KEYACTIONS_FAIL)
				{
					*status = DKIMF_STATUS_BAD;
					result = "policy";
				}
				else if (conf->conf_unprotectedkey == DKIMF_KEYACTIONS_NEUTRAL)
				{
					*status = DKIMF_STATUS_VERIFYERR;
					result = "neutral";
				}
				break;

			  case DKIM_DNSSEC_BOGUS:
				dnssec = "bogus";
				if (conf->conf_boguskey == DKIMF_KEYACTIONS_FAIL)
				{
					*status = DKIMF_STATUS_BAD;
				}
				else if (conf->conf_boguskey == DKIMF_KEYACTIONS_NEUTRAL)			{
					*status = DKIMF_STATUS_VERIFYERR;
					result = "neutral";
				}
				break;

			  case DKIM_DNSSEC_SECURE:
				dnssec = "secure";
				break;
			}
#endif /* USE_UNBOUND */

			memset(val, '\0', sizeof val);

			(void) dkim_sig_getidentity(dkim, sigs[c],
			                            val, sizeof val - 1);

			domain = dkim_sig_getdomain(sigs[c]);

			snprintf(tmp, sizeof tmp,
			         "%s%sdkim=%s%s (%u-bit key%s%s) header.d=%s header.i=%s%s%s",
			         c == 0 ? "" : ";",
			         DELIMITER, result, comment,
			         keybits,
			         dnssec == NULL ? "" : "; ",
			         dnssec == NULL ? "" : dnssec,
			         domain, val,
			         ts == DKIM_STAT_OK ? " header.b=" : "",
			         ts == DKIM_STAT_OK ? ss : "");

			strlcat(hdr, tmp, hdrlen);
		}
	}
}

/*
**  END private section
**  ==================================================================
**  BEGIN milter section
*/

#if SMFI_VERSION >= 0x01000000
/*
**  MLFI_NEGOTIATE -- handler called on new SMTP connection to negotiate
**                    MTA options
**
**  Parameters:
**  	ctx -- milter context
**	f0  -- actions offered by the MTA
**	f1  -- protocol steps offered by the MTA
**	f2  -- reserved for future extensions
**	f3  -- reserved for future extensions
**	pf0 -- actions requested by the milter
**	pf1 -- protocol steps requested by the milter
**	pf2 -- reserved for future extensions
**	pf3 -- reserved for future extensions
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_negotiate(SMFICTX *ctx,
	unsigned long f0, unsigned long f1,
	unsigned long f2, unsigned long f3,
	unsigned long *pf0, unsigned long *pf1,
	unsigned long *pf2, unsigned long *pf3)
{
	unsigned long reqactions = SMFIF_ADDHDRS;
# if defined(SMFIF_SETSYMLIST) && defined(HAVE_SMFI_SETSYMLIST)
	unsigned long wantactions = (SMFIF_SETSYMLIST);
# else /* defined(SMFIF_SETSYMLIST) && defined(HAVE_SMFI_SETSYMLIST) */
	unsigned long wantactions = 0;
# endif /* defined(SMFIF_SETSYMLIST) && defined(HAVE_SMFI_SETSYMLIST) */
	unsigned long protosteps = (SMFIP_NOHELO |
	                            SMFIP_NOUNKNOWN |
	                            SMFIP_NODATA |
	                            SMFIP_SKIP );
	connctx cc;
	struct dkimf_config *conf;

	dkimf_config_reload();

	/* initialize connection context */
	cc = malloc(sizeof(struct connctx));
	if (cc == NULL)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "mlfi_negotiate(): malloc(): %s",
			       strerror(errno));
		}

		return SMFIS_TEMPFAIL;
	}

	memset(cc, '\0', sizeof(struct connctx));

	pthread_mutex_lock(&conf_lock);

	cc->cctx_config = curconf;
	curconf->conf_refcnt++;
	conf = curconf;

	pthread_mutex_unlock(&conf_lock);

	/* verify the actions we need are available */
	if (conf->conf_remarall ||
	    !conf->conf_keepar ||
# ifdef _FFR_IDENTITY_HEADER
	    conf->conf_rmidentityhdr ||
# endif /* _FFR_IDENTITY_HEADER */
# ifdef _FFR_VBR
	    conf->conf_vbr_purge ||
# endif /* _FFR_VBR */
	    conf->conf_remsigs)
		reqactions |= SMFIF_CHGHDRS;

# ifdef SMFIF_QUARANTINE
	if (conf->conf_capture)
		reqactions |= SMFIF_QUARANTINE;
# endif /* SMFIF_QUARANTINE */

	if (conf->conf_redirect != NULL)
	{
		reqactions |= SMFIF_ADDRCPT;
		reqactions |= SMFIF_DELRCPT;
	}

	if ((f0 & reqactions) != reqactions)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "mlfi_negotiate(): required milter action(s) not available (got 0x%lx, need 0x%lx)",
			       f0, reqactions);
		}

		pthread_mutex_lock(&conf_lock);
		conf->conf_refcnt--;
		pthread_mutex_unlock(&conf_lock);

		free(cc);

		return SMFIS_REJECT;
	}

	/* also try to get some nice features */
	wantactions = (wantactions & f0);

	/* set the actions we want */
	*pf0 = (reqactions | wantactions);

	/* disable as many protocol steps we don't need as are available */
	*pf1 = (protosteps & f1);

# ifdef SMFIP_HDR_LEADSPC
	/* request preservation of leading spaces if possible */
	if ((f1 & SMFIP_HDR_LEADSPC) != 0)
	{
		if (cc != NULL)
		{
			cc->cctx_noleadspc = TRUE;
			*pf1 |= SMFIP_HDR_LEADSPC;
		}
	}
# endif /* SMFIP_HDR_LEADSPC */

	*pf2 = 0;
	*pf3 = 0;

	/* request macros if able */
# if defined(SMFIF_SETSYMLIST) && defined(HAVE_SMFI_SETSYMLIST)
	if (conf->conf_macros != NULL && (wantactions & SMFIF_SETSYMLIST) != 0)
	{
		int c;
		char macrolist[BUFRSZ];

		memset(macrolist, '\0', sizeof macrolist);

		strlcpy(macrolist, DKIMF_EOHMACROS, sizeof macrolist);

		for (c = 0; conf->conf_macros[c] != NULL; c++)
		{
			if (macrolist[0] != '\0')
				strlcat(macrolist, " ", sizeof macrolist);

			if (strlcat(macrolist, conf->conf_macros[c],
			            sizeof macrolist) >= sizeof macrolist)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "mlfi_negotiate(): macro list overflow");
				}

				pthread_mutex_lock(&conf_lock);
				conf->conf_refcnt--;
				pthread_mutex_unlock(&conf_lock);

				free(cc);

				return SMFIS_REJECT;
			}
		}

		if (smfi_setsymlist(ctx, SMFIM_EOH, macrolist) != MI_SUCCESS)
		{
			if (conf->conf_dolog)
				syslog(LOG_ERR, "smfi_setsymlist() failed");

			pthread_mutex_lock(&conf_lock);
			conf->conf_refcnt--;
			pthread_mutex_unlock(&conf_lock);

			free(cc);

			return SMFIS_REJECT;
		}
	}
# endif /* defined(SMFIF_SETSYMLIST) && defined(HAVE_SMFI_SETSYMLIST) */

	/* set "milterv2" flag if SMFIP_SKIP was available */
	if ((f1 & SMFIP_SKIP) != 0)
		cc->cctx_milterv2 = TRUE;

	(void) dkimf_setpriv(ctx, cc);

	return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION >= 0x01000000 */

/*
**  MLFI_CONNECT -- connection handler
**
**  Parameters:
**  	ctx -- milter context
**  	host -- hostname
**  	ip -- address, in in_addr form
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_connect(SMFICTX *ctx, char *host, _SOCK_ADDR *ip)
{
	char *err = NULL;
	connctx cc;
	struct dkimf_config *conf;

	dkimf_config_reload();

	if (!dkimf_dns_init(curconf->conf_libopendkim, curconf, &err))
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "can't initialize resolver: %s", err);

		return SMFIS_TEMPFAIL;
	}

	/* copy hostname and IP information to a connection context */
	cc = dkimf_getpriv(ctx);
	if (cc == NULL)
	{
		cc = malloc(sizeof(struct connctx));
		if (cc == NULL)
		{
			pthread_mutex_lock(&conf_lock);

			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s malloc(): %s", host,
				       strerror(errno));
			}

			pthread_mutex_unlock(&conf_lock);

			/* XXX result should depend on On-InternalError */
			return SMFIS_TEMPFAIL;
		}

		memset(cc, '\0', sizeof(struct connctx));

		pthread_mutex_lock(&conf_lock);

		cc->cctx_config = curconf;
		curconf->conf_refcnt++;

		conf = curconf;

		pthread_mutex_unlock(&conf_lock);

		dkimf_setpriv(ctx, cc);
	}
	else
	{
		conf = cc->cctx_config;
	}

	/* if the client is on an ignored host, then ignore it */
	if (conf->conf_peerdb != NULL)
	{
		/* try hostname, if available */
		if (host != NULL && host[0] != '\0' && host[0] != '[')
		{
			dkimf_lowercase((u_char *) host);
			if (dkimf_checkhost(conf->conf_peerdb, host))
				return SMFIS_ACCEPT;
		}

		/* try IP address, if available */
		if (ip != NULL && (ip->sa_family == AF_INET
#ifdef AF_INET6
			|| ip->sa_family == AF_INET6
#endif /* AF_INET6 */
			))
		{
			if (dkimf_checkip(conf->conf_peerdb, ip))
				return SMFIS_ACCEPT;
		}
	}

	if (host != NULL)
		strlcpy(cc->cctx_host, host, sizeof cc->cctx_host);

	if (ip == NULL)
	{
		struct sockaddr_in sin;

		memset(&sin, '\0', sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		memcpy(&cc->cctx_ip, &sin, sizeof sin);
	}
	else if (ip->sa_family == AF_INET)
	{
		memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in));
	}
#ifdef AF_INET6
	else if (ip->sa_family == AF_INET6)
	{
		memcpy(&cc->cctx_ip, ip, sizeof(struct sockaddr_in6));
	}
#endif /* AF_INET6 */

	cc->cctx_msg = NULL;

	return SMFIS_CONTINUE;
}

#if SMFI_VERSION == 2
/*
**  MLFI_HELO -- handler for HELO/EHLO command (start of message)
**
**  Parameters:
**  	ctx -- milter context
**  	helo -- HELO/EHLO parameter
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_helo(SMFICTX *ctx, char *helo)
{
	assert(ctx != NULL);
	assert(helo != NULL);

	return SMFIS_CONTINUE;
}
#endif /* SMFI_VERSION == 2 */

/*
**  MLFI_ENVFROM -- handler for MAIL FROM command (start of message)
**
**  Parameters:
**  	ctx -- milter context
**  	envfrom -- envelope from arguments
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	connctx cc;
	msgctx dfc;
	struct dkimf_config *conf;

	assert(ctx != NULL);
	assert(envfrom != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	conf = cc->cctx_config;

	/*
	**  Initialize a filter context.
	*/

	dkimf_cleanup(ctx);
	dfc = dkimf_initcontext(conf);
	if (dfc == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "message requeueing (internal error)");
		}

		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	if (envfrom[0] != NULL)
	{
		size_t len;
		unsigned char *p;
		unsigned char *q;

		strlcpy(dfc->mctx_envfrom, envfrom[0],
		        sizeof dfc->mctx_envfrom);

		len = strlen(dfc->mctx_envfrom);
		p = dfc->mctx_envfrom;
		q = dfc->mctx_envfrom + len - 1;

		while (len >= 2 && *p == '<' && *q == '>')
		{
			p++;
			q--;
			len -= 2;
		}

		if (p != dfc->mctx_envfrom)
		{
			*(q + 1) = '\0';
			memmove(dfc->mctx_envfrom, p, len + 1);
		}
	}

	/*
	**  Save it in this thread's private space.
	*/

	cc->cctx_msg = dfc;

	/*
	**  Continue processing.
	*/

	return SMFIS_CONTINUE;
}

/*
**  MLFI_ENVRCPT -- handler for RCPT TO command
**
**  Parameters:
**  	ctx -- milter context
**  	envrcpt -- envelope rcpt to arguments
**
**  Return value:
**  	SMFIS_CONTINUE
*/

sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **envrcpt)
{
	char *copy;
	connctx cc;
	msgctx dfc;
	struct dkimf_config *conf;
	char addr[MAXADDRESS + 1];

	assert(ctx != NULL);
	assert(envrcpt != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	if (conf->conf_dontsigntodb != NULL
	    || conf->conf_bldb != NULL
	    || conf->conf_redirect != NULL
#ifdef _FFR_RESIGN
	    || conf->conf_resigndb != NULL
#endif /* _FFR_RESIGN */
#ifdef USE_LUA
	    || conf->conf_setupscript != NULL
	    || conf->conf_screenscript != NULL
	    || conf->conf_finalscript != NULL
# ifdef _FFR_STATSEXT
	    || conf->conf_statsscript != NULL
# endif /* _FFR_STATSEXT */
#endif /* USE_LUA */
	   )
	{
		strlcpy(addr, envrcpt[0], sizeof addr);
		dkimf_stripbrackets(addr);
	}

	if (conf->conf_dontsigntodb != NULL
	    || conf->conf_bldb != NULL
	    || conf->conf_redirect != NULL
#ifdef _FFR_RESIGN
	    || conf->conf_resigndb != NULL
#endif /* _FFR_RESIGN */
#ifdef USE_LUA
	    || conf->conf_setupscript != NULL
	    || conf->conf_screenscript != NULL
	    || conf->conf_finalscript != NULL
# ifdef _FFR_STATSEXT
	    || conf->conf_statsscript != NULL
# endif /* _FFR_STATSEXT */
#endif /* USE_LUA */
	   )
	{
		struct addrlist *a;

		copy = strdup(addr);
		if (copy == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "message requeueing (internal error)");
			}

			free(copy);
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}

		a = (struct addrlist *) malloc(sizeof(struct addrlist));
		if (a == NULL)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "message requeueing (internal error)");
			}

			free(copy);
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}

		a->a_next = dfc->mctx_rcptlist;
		a->a_addr = copy;

		dfc->mctx_rcptlist = a;
	}

	return SMFIS_CONTINUE;
}

/*
**  MLFI_HEADER -- handler for mail headers; stores the header in a vector
**                 of headers for later perusal, removing RFC822 comment
**                 substrings
**
**  Parameters:
**  	ctx -- milter context
**  	headerf -- header
**  	headerv -- value
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
#ifdef _FFR_REPLACE_RULES
	_Bool dorepl = FALSE;
#endif /* _FFR_REPLACE_RULES */
	msgctx dfc;
	connctx cc;
	Header newhdr;
	struct dkimf_config *conf;

	assert(ctx != NULL);
	assert(headerf != NULL);
	assert(headerv != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	/* check for too much header data */
	if (conf->conf_maxhdrsz > 0 &&
	    dfc->mctx_hdrbytes + strlen(headerf) + strlen(headerv) + 2 > conf->conf_maxhdrsz)
	{
		if (conf->conf_dolog)
			syslog(LOG_NOTICE, "too much header data");

		return dkimf_miltercode(ctx,
		                        conf->conf_handling.hndl_security,
		                        NULL);
	}

	/*
	**  Completely ignore a field name containing a semicolon; this is
	**  strangely legal by RFC5322, but completely incompatible with DKIM.
	*/

	if (strchr(headerf, ';') != NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_NOTICE, "ignoring header field '%s'",
			       headerf);
		}

		return SMFIS_CONTINUE;
	}

	newhdr = (Header) malloc(sizeof(struct Header));
	if (newhdr == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

#ifdef _FFR_REPUTATION
# ifdef USE_GNUTLS
	(void) gnutls_hash(dfc->mctx_hash, headerf, strlen(headerf));
	(void) gnutls_hash(dfc->mctx_hash, headerv, strlen(headerv));
# else /* USE_GNUTLS */
	SHA1_Update(&dfc->mctx_hash, headerf, strlen(headerf));
	SHA1_Update(&dfc->mctx_hash, headerv, strlen(headerv));
# endif /* USE_GNUTLS */
#endif /* _FFR_REPUTATION */

	(void) memset(newhdr, '\0', sizeof(struct Header));

	newhdr->hdr_hdr = strdup(headerf);

	if (dfc->mctx_tmpstr == NULL)
	{
		dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);
		if (dfc->mctx_tmpstr == NULL)
		{
			if (conf->conf_dolog)
				syslog(LOG_ERR, "dkimf_dstring_new() failed");

			TRYFREE(newhdr->hdr_hdr);
			free(newhdr);

			dkimf_cleanup(ctx);

			return SMFIS_TEMPFAIL;
		}
	}
	else
	{
		dkimf_dstring_blank(dfc->mctx_tmpstr);
	}

	if (!cc->cctx_noleadspc)
	{
		/*
		**  The sendmail MTA does some minor header rewriting on
		**  outgoing mail.  This makes things slightly prettier for
		**  the MUA, but these changes are made after this filter has
		**  already generated and added a signature.  As a result,
		**  verification of the signature will fail because what got
		**  signed isn't the same as what actually goes out.  This
		**  chunk of code attempts to compensate by arranging to
		**  feed to the canonicalization algorithms the headers
		**  exactly as the MTA will modify them, so verification
		**  should still work.
		**  
		**  This is based on experimentation and on reading
		**  sendmail/headers.c, and may require more tweaking before
		**  it's precisely right.  There are other munges the
		**  sendmail MTA makes which are not (yet) addressed by this
		**  code.
		**
		**  This should not be used with sendmail 8.14 and later as
		**  it is not required; that version of sendmail and
		**  libmilter handles the munging correctly (by suppressing
		**  it).
		*/

		char *p;

		p = headerv;
		while (isascii(*p) && isspace(*p))
			p++;

		dkimf_dstring_copy(dfc->mctx_tmpstr, (u_char *) p);
	}
	else
	{
		dkimf_dstring_copy(dfc->mctx_tmpstr, (u_char *) headerv);
	}

#ifdef _FFR_REPLACE_RULES
	if (conf->conf_rephdrsdb == NULL)
	{
		dorepl = TRUE;
	}
	else
	{
		_Bool found;

		found = FALSE;

		if (dkimf_db_get(conf->conf_rephdrsdb,
		                 (char *) headerf, 0, NULL, 0,
		                 &found) != 0)
		{
			if (conf->conf_dolog)
				syslog(LOG_ERR, "dkimf_db_get() failed");

			return SMFIS_TEMPFAIL;
		}

		dorepl = found;
	}

	if (conf->conf_replist != NULL && dorepl)
	{
		int status;
		regmatch_t match;
		char *str;
		struct dkimf_dstring *tmphdr = NULL;
		struct replace *rep;

		tmphdr = dkimf_dstring_new(BUFRSZ, 0);
		if (tmphdr == NULL)
		{
			if (conf->conf_dolog)
				syslog(LOG_ERR, "dkimf_dstring_new() failed");

			TRYFREE(newhdr->hdr_hdr);
			free(newhdr);

			dkimf_cleanup(ctx);

			return SMFIS_TEMPFAIL;
		}
	
		for (rep = conf->conf_replist;
		     rep != NULL;
		     rep = rep->repl_next)
		{
			str = dkimf_dstring_get(dfc->mctx_tmpstr);

			for (;;)
			{
				status = regexec(&rep->repl_re, str, 1,
				                 &match, 0);

				if (status == REG_NOMATCH)
				{
					break;
				}
				else if (status != 0)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "regexec() failed");
					}

					TRYFREE(newhdr->hdr_hdr);
					free(newhdr);
					dkimf_dstring_free(tmphdr);
					dkimf_cleanup(ctx);

					return SMFIS_TEMPFAIL;
				}

				dkimf_dstring_blank(tmphdr);

				dkimf_dstring_copy(tmphdr, str);
				dkimf_dstring_chop(tmphdr, match.rm_so);
				dkimf_dstring_cat(tmphdr, rep->repl_txt);
				dkimf_dstring_cat(tmphdr, str + match.rm_eo);

				dkimf_dstring_blank(dfc->mctx_tmpstr);
				str = dkimf_dstring_get(tmphdr);
				dkimf_dstring_cat(dfc->mctx_tmpstr, str);
			}
		}

		dkimf_dstring_free(tmphdr);
	}
#endif /* _FFR_REPLACE_RULES */

	newhdr->hdr_val = strdup((char *) dkimf_dstring_get(dfc->mctx_tmpstr));

	newhdr->hdr_next = NULL;
	newhdr->hdr_prev = dfc->mctx_hqtail;

	if (newhdr->hdr_hdr == NULL || newhdr->hdr_val == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		TRYFREE(newhdr->hdr_hdr);
		TRYFREE(newhdr->hdr_val);
		TRYFREE(newhdr);
		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	dfc->mctx_hdrbytes += strlen(newhdr->hdr_hdr) + 1;
	dfc->mctx_hdrbytes += strlen(newhdr->hdr_val) + 1;

	if (dfc->mctx_hqhead == NULL)
		dfc->mctx_hqhead = newhdr;

	if (dfc->mctx_hqtail != NULL)
		dfc->mctx_hqtail->hdr_next = newhdr;

	dfc->mctx_hqtail = newhdr;

	if (strcasecmp(headerf, conf->conf_selectcanonhdr) == 0)
	{
		int c;
		char *slash;

		slash = strchr(headerv, '/');
		if (slash != NULL)
		{
			*slash = '\0';

			c = dkimf_lookup_strtoint(headerv, dkimf_canon);
			if (c != -1)
				dfc->mctx_hdrcanon = (dkim_canon_t) c;
			c = dkimf_lookup_strtoint(slash + 1, dkimf_canon);
			if (c != -1)
				dfc->mctx_bodycanon = (dkim_canon_t) c;

			*slash = '/';
		}
		else
		{
			c = dkimf_lookup_strtoint(headerv, dkimf_canon);
			if (c != -1)
				dfc->mctx_hdrcanon = (dkim_canon_t) c;
		}

		/* XXX -- eat this header? */
	}

	return SMFIS_CONTINUE;
}

/*
**  MLFI_EOH -- handler called when there are no more headers
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eoh(SMFICTX *ctx)
{
	char last;
	_Bool setidentity = FALSE;
	_Bool domainok;
	_Bool originok;
	_Bool didfrom = FALSE;
#ifdef _FFR_RESIGN
	_Bool msgsigned = FALSE;
#endif /* _FFR_RESIGN */
	int c;
	DKIM_STAT status;
	sfsistat ms = SMFIS_CONTINUE;
	connctx cc;
	msgctx dfc;
	DKIM *lastdkim;
	char *p;
#ifdef _FFR_SENDER_MACRO
	char *macrosender = NULL;
#endif /* _FFR_SENDER_MACRO */
	u_char *user;
	u_char *domain;
#ifdef _FFR_VBR
	char *vbr_cert = NULL;
	char *vbr_type = NULL;
#endif /* _FFR_VBR */
	struct dkimf_config *conf;
	struct dkimf_dstring *addr;
	Header from = NULL;
	Header hdr;

	assert(ctx != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	/*
	**  Determine the message ID for logging.
	*/

	dfc->mctx_jobid = (u_char *) dkimf_getsymval(ctx, "i");
	if (dfc->mctx_jobid == NULL || dfc->mctx_jobid[0] == '\0')
		dfc->mctx_jobid = (u_char *) JOBIDUNKNOWN;

	/* find the Sender: or From: header */
	addr = dkimf_dstring_new(BUFRSZ, 0);

#ifdef _FFR_SENDER_MACRO
	if (conf->conf_sendermacro != NULL)
	{
		macrosender = dkimf_getsymval(ctx, conf->conf_sendermacro);
		if (macrosender != NULL)
			dkimf_dstring_copy(addr, macrosender);
	}
#endif /* _FFR_SENDER_MACRO */

  	if (dkimf_dstring_len(addr) == 0)
	{
		for (c = 0; conf->conf_senderhdrs != NULL &&
                            conf->conf_senderhdrs[c] != NULL; c++)
		{
			if (strcasecmp("from", conf->conf_senderhdrs[c]) == 0)
				didfrom = TRUE;

			from = dkimf_findheader(dfc, conf->conf_senderhdrs[c],
			                        0);
			if (from != NULL)
				break;
		}

		if (from == NULL && !didfrom)
			from = dkimf_findheader(dfc, "from", 0);
	}
  
  	if (from != NULL)
		dkimf_dstring_copy(addr, from->hdr_val);

	if (dkimf_dstring_len(addr) == 0)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "%s: can't determine message sender; accepting",
			       dfc->mctx_jobid);
		}

		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
		dkimf_dstring_free(addr);
		return SMFIS_CONTINUE;
	}

	status = dkim_mail_parse(dkimf_dstring_get(addr), &user, &domain);

#ifdef _FFR_DEFAULT_SENDER
	if (conf->conf_defsender != NULL &&
	    (status != 0 || user == NULL || domain == NULL ||
	     user[0] == '\0' || domain[0] == '\0'))
	{
		strlcpy(addr, conf->conf_defsender, sizeof addr);
		status = dkim_mail_parse(addr, &user, &domain);
	}
#endif /* _FFR_DEFAULT_SENDER */

	if ((conf->conf_mode & DKIMF_MODE_SIGNER) != 0 &&
	    (status != 0 || user == NULL || domain == NULL ||
	     user[0] == '\0' || domain[0] == '\0'))
	{
		if (conf->conf_dolog)
		{
#ifdef _FFR_SENDER_MACRO
			if (macrosender != NULL)
			{
				syslog(LOG_INFO,
				       "%s: can't parse macro %s header value '%s'",
				       dfc->mctx_jobid, conf->conf_sendermacro,
				       macrosender);
			}
			else
#endif /* _FFR_SENDER_MACRO */
			if (from != NULL)
			{
				syslog(LOG_INFO,
				       "%s: can't parse %s: header value '%s'",
				       dfc->mctx_jobid, from->hdr_hdr,
				       from->hdr_val);
			}
#ifdef _FFR_DEFAULT_SENDER
			else if (conf->conf_defsender != NULL)
			{
				syslog(LOG_INFO,
				       "%s: can't parse default sender value '%s'",
				       dfc->mctx_jobid, conf->conf_defsender);
			}
#endif /* _FFR_DEFAULT_SENDER */
		}

		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
		dkimf_dstring_free(addr);
		return SMFIS_CONTINUE;
	}

	if (domain != NULL)
	{
		strlcpy((char *) dfc->mctx_domain, (char *) domain,
		        sizeof dfc->mctx_domain);
		dkimf_lowercase(dfc->mctx_domain);
	}

	/* if it's exempt, bail out */
	if (conf->conf_exemptdb != NULL && dfc->mctx_domain[0] != '\0')
	{
		_Bool match = FALSE;
		int status;

		status = dkimf_db_get(conf->conf_exemptdb,
		                      dfc->mctx_domain, 0, NULL, 0,
		                      &match);
		if (status != 0)
		{
			if (dolog)
			{
				dkimf_db_error(conf->conf_exemptdb,
				               (char *) dfc->mctx_domain);
			}

			dkimf_dstring_free(addr);
			return SMFIS_TEMPFAIL;
		}

		if (match)
		{
			if (conf->conf_logwhy)
			{
				syslog(LOG_INFO,
				       "%s: domain '%s' exempted, accepting",
				       dfc->mctx_jobid, dfc->mctx_domain);
			}

			dkimf_cleanup(ctx);
			dkimf_dstring_free(addr);
			return SMFIS_ACCEPT;
		}
	}

	/* apply BodyLengthDB if signing */
	if (conf->conf_bldb != NULL && !dfc->mctx_bldbdone)
	{
		struct addrlist *a;

		for (a = dfc->mctx_rcptlist; a != NULL; a = a->a_next)
		{
	    		if (dkimf_checkbldb(conf->conf_bldb, a->a_addr,
			                    dfc->mctx_jobid))
			{
				dfc->mctx_ltag = TRUE;
				dfc->mctx_laddr = a->a_addr;
				break;
			}
		}

		dfc->mctx_bldbdone = TRUE;
	}

	/* assume we're not signing */
	dfc->mctx_signalg = DKIM_SIGN_UNKNOWN;
	domainok = FALSE;
	originok = FALSE;

#ifdef _FFR_RESIGN
	msgsigned = (dkimf_findheader(dfc, DKIM_SIGNHEADER, 0) != NULL);

	/* check to see if it's a destination for which we resign */
	if (conf->conf_resigndb != NULL)
	{
		bool match = FALSE;
		char *at;
		char *dot;
		struct addrlist *a;
		char resignkey[BUFRSZ + 1];
		struct dkimf_db_data dbd;

		memset(resignkey, '\0', sizeof resignkey);

		dbd.dbdata_buffer = resignkey;
		dbd.dbdata_buflen = sizeof resignkey;
		dbd.dbdata_flags = 0;

		for (a = dfc->mctx_rcptlist; a != NULL; a = a->a_next)
		{
			/* full recipient address */
			if (dkimf_db_get(conf->conf_resigndb, a->a_addr, 0,
			                 &dbd, 1, &match) != 0)
			{
				if (dolog)
				{
					dkimf_db_error(conf->conf_resigndb,
					               a->a_addr);
				}
				continue;
			}

			if (match)
			{
				domainok = TRUE;
				originok = TRUE;
				dfc->mctx_resign = TRUE;
				break;
			}

			/* hostname only */
			at = strchr(a->a_addr, '@');
			if (at == NULL)
				continue;

			status = dkimf_db_get(conf->conf_resigndb,
			                      at + 1, 0, &dbd, 1,
			                      &match);

			if (status != 0)
			{
				if (dolog)
				{
					dkimf_db_error(conf->conf_resigndb,
					               at + 1);
				}
				continue;
			}

			if (match)
			{
				domainok = TRUE;
				originok = TRUE;
				dfc->mctx_resign = TRUE;
				break;
			}

			/* iterate through ".domain" possibilities */
			for (dot = strchr(at, '.');
			     dot != NULL;
			     dot = strchr(dot + 1, '.'))
			{
				status = dkimf_db_get(conf->conf_resigndb,
				                      dot, 0, &dbd, 1,
				                      &match);
				if (status != 0)
				{
					if (dolog)
					{
						dkimf_db_error(conf->conf_resigndb,
					                       dot);
					}

					continue;
				}

				if (match)
					break;
			}

			if (match)
			{
				domainok = TRUE;
				originok = TRUE;
				dfc->mctx_resign = TRUE;
				break;
			}
		}

		if (match)
		{
			if (conf->conf_keytabledb == NULL ||
			    resignkey[0] == '\0')
			{
				status = dkimf_add_signrequest(dfc, NULL, NULL,
				                               NULL,
				                               (ssize_t) -1);

				if (status != 0)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s: failed to add signature for default key",
						       dfc->mctx_jobid);
					}

					dkimf_dstring_free(addr);
					return SMFIS_TEMPFAIL;
				}
			}
			else
			{
				status = dkimf_add_signrequest(dfc,
				                               conf->conf_keytabledb,
				                               resignkey,
				                               NULL,
				                               (ssize_t) -1);

				if (status != 0)
				{
					if (dolog)
					{
						syslog(LOG_ERR,
						       "%s: failed to add signature for key '%s'",
						       dfc->mctx_jobid,
						       resignkey);
					}

					dkimf_dstring_free(addr);
					return SMFIS_TEMPFAIL;
				}
			}
		}
	}
#endif /* _FFR_RESIGN */

	/* see if it came in on an authorized MSA/MTA connection */
	if (conf->conf_mtasdb != NULL)
	{
		char *mtaname;
		char *host;

		mtaname = dkimf_getsymval(ctx, "{daemon_name}");
		host = dkimf_getsymval(ctx, "j");
		status = 0;

		if (mtaname != NULL)
		{
			status = dkimf_db_get(conf->conf_mtasdb, mtaname, 0,
			                      NULL, 0, &originok);
			if (status != 0 && dolog)
				dkimf_db_error(conf->conf_mtasdb, mtaname);
		}

		if (!originok && status == 0 && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s: no MTA name match (host=%s, MTA=%s)",
			       dfc->mctx_jobid, host,
			       mtaname == NULL ? "?" : mtaname);
		}
	}

	/* see if macro tests passed */
	if (conf->conf_macrosdb != NULL)
	{
		_Bool done = FALSE;
		int n;
		char *val;
		char name[BUFRSZ + 1];
		struct dkimf_db_data dbd;

		if (dfc->mctx_tmpstr == NULL)
		{
			dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);
			if (dfc->mctx_tmpstr == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: dkimf_dstring_new() failed",
					       dfc->mctx_jobid);
				}

				dkimf_cleanup(ctx);
				dkimf_dstring_free(addr);
				return SMFIS_TEMPFAIL;
			}
		}

		for (n = 0; !done && conf->conf_macros[n] != NULL; n++)
		{
			/* retrieve the macro */
			snprintf(name, sizeof name, "{%s}",
			         conf->conf_macros[n]);
			val = dkimf_getsymval(ctx, name);

			/* short-circuit if the macro's not set */
			if (val == NULL)
				continue;

			memset(&dbd, '\0', sizeof dbd);
			dbd.dbdata_buffer = val;
			dbd.dbdata_buflen = strlen(val) + 1;
			dbd.dbdata_flags = 0;

			status = dkimf_db_get(conf->conf_macrosdb,
			                      conf->conf_macros[n], 0,
			                      &dbd, 1, &originok);
			if (status != 0 && dolog)
				dkimf_db_error(conf->conf_macrosdb, name);
		}

		if (!originok && conf->conf_logwhy)
		{
			syslog(LOG_INFO, "%s: no macros match",
			       dfc->mctx_jobid);
		}
	}

	/* see if it came from an internal or authenticated source */
	if (!originok)
	{
		_Bool internal;
#ifdef POPAUTH
		_Bool popauth;
#endif /* POPAUTH */
		char *authtype;

		internal = dkimf_checkhost(conf->conf_internal, cc->cctx_host);
		internal = internal || dkimf_checkip(conf->conf_internal,
		                                     (struct sockaddr *) &cc->cctx_ip);

		authtype = dkimf_getsymval(ctx, "{auth_type}");

#ifdef POPAUTH
		popauth = dkimf_checkpopauth(popdb,
		                             (struct sockaddr *) &cc->cctx_ip);
#endif /* POPAUTH */

		if ((authtype != NULL && authtype[0] != '\0') || internal)
			originok = TRUE;

#ifdef POPAUTH
		if (popauth)
			originok = TRUE;
#endif /* POPAUTH */

		if (!originok && conf->conf_logwhy)
		{
			if (!internal)
			{
				char ipbuf[BUFRSZ];

				dkimf_ipstring(ipbuf, sizeof ipbuf,
				               &cc->cctx_ip);
				syslog(LOG_INFO, "%s: %s [%s] not internal",
				       dfc->mctx_jobid, cc->cctx_host,
				       ipbuf);
			}

			if (authtype == NULL || authtype[0] == '\0')
			{
				syslog(LOG_INFO, "%s: not authenticated",
				       dfc->mctx_jobid);
			}

#ifdef POPAUTH
			if (!popauth)
			{
				syslog(LOG_INFO, "%s: not POP authenticated",
				       dfc->mctx_jobid);
			}
#endif /* POPAUTH */
		}
	}

	/* is it a domain we sign for? */
	if (!domainok && conf->conf_domainsdb != NULL)
	{
		status = dkimf_db_get(conf->conf_domainsdb, dfc->mctx_domain,
		                      0, NULL, 0, &domainok);

		if (!domainok)
		{
			/* check for "*" for back-compatibility */
			status = dkimf_db_get(conf->conf_domainsdb, "*",
			                      0, NULL, 0, &domainok);
			if (status != 0 && dolog)
				dkimf_db_error(conf->conf_domainsdb, "*");
		}

		if (!domainok && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s: no signing domain match for '%s'",
			       dfc->mctx_jobid, dfc->mctx_domain);
		}

		if (conf->conf_subdomains && !domainok)
		{
			for (p = strchr((char *) dfc->mctx_domain, '.');
			     p != NULL && !domainok;
			     p = strchr(p, '.'))
			{
				p++;
				if (*p == '\0')
					break;

				status = dkimf_db_get(conf->conf_domainsdb, p,
				                      0, NULL, 0,
				                      &domainok);
				if (status != 0)
				{
					if (dolog)
					{
						dkimf_db_error(conf->conf_domainsdb,
						               p);
					}

					continue;
				}

				if (domainok)
				{
					strlcpy((char *) dfc->mctx_domain, p,
					        sizeof dfc->mctx_domain);
					break;
				}
			}

			if (domainok)
				setidentity = TRUE;
		}

		if (!domainok && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s: no signing subdomain match for '%s'",
			       dfc->mctx_jobid, dfc->mctx_domain);
		}
	}

	/* warn if the domain was OK but didn't come from a safe source */
	if (domainok && !originok)
	{
		if (conf->conf_dolog &&
		    !dkimf_checkhost(conf->conf_exignore, cc->cctx_host) &&
		    !dkimf_checkip(conf->conf_exignore,
		                   (struct sockaddr *) &cc->cctx_ip))
		{
			syslog(LOG_NOTICE,
			       "%s: external host %s attempted to send as %s",
			       dfc->mctx_jobid, cc->cctx_host,
			       dfc->mctx_domain);
		}
	}

	/* still no key selected; check the signing table (if any) */
	if (originok && dfc->mctx_srhead == NULL &&
	    (user != NULL && dfc->mctx_domain[0] != '\0') && 
#ifdef _FFR_LUA_ONLY_SIGNING
	    !conf->conf_luasigning &&
#endif /* _FFR_LUA_ONLY_SIGNING */
	    conf->conf_keytabledb != NULL && conf->conf_signtabledb != NULL)
	{
		int found;
		char errkey[BUFRSZ + 1];

		memset(errkey, '\0', sizeof errkey);
		found = dkimf_apply_signtable(dfc, conf->conf_keytabledb,
		                              conf->conf_signtabledb,
		                              user, dfc->mctx_domain,
		                              errkey, sizeof errkey,
		                              conf->conf_multisig);

		if (found < 0)
		{
			if (conf->conf_dolog)
			{
				switch (found)
				{
				  case -1:
					syslog(LOG_ERR,
					       "%s: error reading signing table",
					       dfc->mctx_jobid);
					break;

				  case -2:
					syslog(LOG_ERR,
					       "%s: signing table references unknown key '%s'",
					       dfc->mctx_jobid, errkey);
					break;

				  case -3:
					syslog(LOG_ERR,
					       "%s: error loading key '%s'",
					       dfc->mctx_jobid, errkey);
					break;

				  default:
					assert(0);
				}
			}

			dkimf_dstring_free(addr);
			return SMFIS_TEMPFAIL;
		}
		else if (found > 0)
		{
			domainok = TRUE;
		}

		if (!domainok && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s: no signing table match for '%s@%s'",
			       dfc->mctx_jobid, user, dfc->mctx_domain);
		}
	}

	/* don't need the sender field anymore */
	dkimf_dstring_free(addr);

	/* set signing mode if the tests passed */
	if (domainok && originok)
	{
		dfc->mctx_signalg = conf->conf_signalg;
		dfc->mctx_addheader = TRUE;
	}

	/* remember internal state */
	dfc->mctx_internal = originok;

#ifdef USE_LUA
	/* invoke the setup script if defined */
	if (conf->conf_setupscript != NULL)
	{
		_Bool dofree = TRUE;
		struct dkimf_lua_script_result lres;

		memset(&lres, '\0', sizeof lres);

		dfc->mctx_mresult = SMFIS_CONTINUE;

		status = dkimf_lua_setup_hook(ctx, conf->conf_setupfunc,
		                              conf->conf_setupfuncsz,
		                              "setup script", &lres,
		                              NULL, NULL);

		if (status != 0)
		{
			if (conf->conf_dolog)
			{
				if (lres.lrs_error == NULL)
				{
					dofree = FALSE;

					switch (status)
					{
					  case 2:
						lres.lrs_error = "processing error";
						break;

					  case 1:
						lres.lrs_error = "syntax error";
						break;

					  case -1:
						lres.lrs_error = "memory allocation error";
						break;

					  default:
						lres.lrs_error = "unknown error";
						break;
					}
				}

				syslog(LOG_ERR,
				       "%s: dkimf_lua_setup_hook() failed: %s",
				       dfc->mctx_jobid, lres.lrs_error);
			}

			if (dofree)
				free(lres.lrs_error);

			return SMFIS_TEMPFAIL;
		}

		if (dfc->mctx_mresult != SMFIS_CONTINUE)
			return dfc->mctx_mresult;
	}
#endif /* USE_LUA */

	/* create a default signing request if there was a domain match */
	if (domainok && originok && dfc->mctx_srhead == NULL)
	{
		status = dkimf_add_signrequest(dfc, NULL, NULL, NULL,
		                               (ssize_t) -1);

		if (status != 0)
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "%s: failed to add default signing request",
				       dfc->mctx_jobid);
			}

			return SMFIS_TEMPFAIL;
		}
	}

	/*
	**  If we're not operating in the role matching the required operation,
	**  just accept the message and be done with it.
	*/

	/* signing requests with signing mode disabled */
	if (dfc->mctx_srhead != NULL && 
	    (conf->conf_mode & DKIMF_MODE_SIGNER) == 0)
		return SMFIS_ACCEPT;

	/* verify request with verify mode disabled */
#ifdef _FFR_RESIGN
	if ((dfc->mctx_srhead == NULL || dfc->mctx_resign) &&
#else /* _FFR_RESIGN */
	if (dfc->mctx_srhead == NULL &&
#endif /* _FFR_RESIGN */
	    (conf->conf_mode & DKIMF_MODE_VERIFIER) == 0)
		return SMFIS_ACCEPT;

	/* check for "DontSignMailTo" */
	if (dfc->mctx_srhead != NULL && conf->conf_dontsigntodb != NULL)
	{
		_Bool found;
		int status;
		struct addrlist *a;

		a = dfc->mctx_rcptlist;

		while (a != NULL)
		{
			found = FALSE;
			status = dkimf_db_get(conf->conf_dontsigntodb,
			                      a->a_addr, 0, NULL, 0,
			                      &found);
			if (found)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_INFO,
					       "%s: skipping signing of mail to '%s'",
					       dfc->mctx_jobid,
					       a->a_addr);
				}

				return SMFIS_ACCEPT;
			}
			else if (status != 0)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: dkimf_db_get() failed",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}

			a = a->a_next;
		}
	}

#ifdef _FFR_RESIGN
	/* if we're not signing, or we are resigning, grab a verify handle */
	if (dfc->mctx_srhead == NULL || dfc->mctx_resign)
#else /* _FFR_RESIGN */
	/* if we're not signing, grab a verify handle */
	if (dfc->mctx_srhead == NULL)
#endif /* _FFR_RESIGN */
	{
		dfc->mctx_dkimv = dkim_verify(conf->conf_libopendkim,
		                              dfc->mctx_jobid, NULL,
		                              &status);

		if (dfc->mctx_dkimv == NULL && status != DKIM_STAT_OK)
		{
			return dkimf_libstatus(ctx, NULL, "dkim_verify()",
			                       status);
		}
	}

#ifdef _FFR_RESIGN
	if (!msgsigned)
	{
		/*
		**  If the message was unsigned, we're just signing and not
		**  resigning.
		*/

		dfc->mctx_resign = FALSE;
	}
#endif /* _FFR_RESIGN */

	/* create all required signing handles */
	if (dfc->mctx_srhead != NULL)
	{
#ifdef _FFR_ATPS
		_Bool atps = FALSE;
#endif /* _FFR_ATPS */
		ssize_t signlen;
		u_char *sdomain;
		u_char *selector;
		struct signreq *sr;
		dkim_sigkey_t keydata;

		if (conf->conf_dolog && dfc->mctx_laddr != NULL)
		{
			syslog(LOG_INFO,
				"%s: BodyLengthDB matched %s, signing with l= requested",
				dfc->mctx_jobid, dfc->mctx_laddr);
		}

#ifdef _FFR_ATPS
		if (conf->conf_atpsdb != NULL)
		{
			status = dkimf_db_get(conf->conf_atpsdb,
			                      dfc->mctx_domain, 0, NULL, 0,
			                      &atps);
			if (status != 0 && dolog)
			{
				dkimf_db_error(conf->conf_atpsdb,
				               dfc->mctx_domain);
			}
		}
#endif /* _FFR_ATPS */

		for (sr = dfc->mctx_srhead; sr != NULL; sr = sr->srq_next)
		{
			if (sr->srq_signlen == (ssize_t) -1)
				signlen = conf->conf_signbytes;
			else
				signlen = sr->srq_signlen;

			if (sr->srq_keydata != NULL)
			{
				keydata = sr->srq_keydata;
				selector = sr->srq_selector;
				if (sr->srq_domain != NULL)
					sdomain = sr->srq_domain;
				else
					sdomain = dfc->mctx_domain;
			}
			else
			{
				sdomain = dfc->mctx_domain;
				keydata = (dkim_sigkey_t) conf->conf_seckey;
				selector = conf->conf_selector;
			}

			sr->srq_dkim = dkim_sign(conf->conf_libopendkim,
			                         dfc->mctx_jobid,
			                         NULL, keydata, selector,
			                         sdomain,
			                         dfc->mctx_hdrcanon,
			                         dfc->mctx_bodycanon,
			                         dfc->mctx_signalg,
			                         signlen, &status);

			if (sr->srq_dkim == NULL || status != DKIM_STAT_OK)
			{
				return dkimf_libstatus(ctx, NULL,
				                       "dkim_sign()",
				                       status);
			}

			if (conf->conf_reqreports)
			{
				status = dkim_add_xtag(sr->srq_dkim,
				                       DKIM_REPORTTAG,
				                       DKIM_REPORTTAGVAL);

				if (status != DKIM_STAT_OK && dolog)
				{
					syslog(LOG_ERR,
					       "%s dkim_add_xtag() for \"%s\" failed",
					       dfc->mctx_jobid,
					       DKIM_REPORTTAG);
				}
			}

#ifdef _FFR_ATPS
			if (atps)
			{
				status = dkim_add_xtag(sr->srq_dkim,
				                       DKIM_ATPSTAG,
				                       dfc->mctx_domain);
				if (status != DKIM_STAT_OK && dolog)
				{
					syslog(LOG_ERR,
					       "%s dkim_add_xtag() for \"%s\" failed",
					       dfc->mctx_jobid, DKIM_ATPSTAG);
				}

				status = dkim_add_xtag(sr->srq_dkim,
				                       DKIM_ATPSHTAG,
				                       conf->conf_atpshash);
				if (status != DKIM_STAT_OK && dolog)
				{
					syslog(LOG_ERR,
					       "%s dkim_add_xtag() for \"%s\" failed",
					       dfc->mctx_jobid, DKIM_ATPSHTAG);
				}
			}
#endif /* _FFR_ATPS */

			(void) dkim_set_user_context(sr->srq_dkim, ctx);

			if (sr->srq_signer != NULL)
			{
				(void) dkim_set_signer(sr->srq_dkim,
				                       sr->srq_signer);
			}

#ifdef _FFR_RESIGN
			if (dfc->mctx_resign && dfc->mctx_dkimv != NULL)
			{
				status = dkim_resign(sr->srq_dkim,
				                     dfc->mctx_dkimv,
				                     FALSE);
				if (status != DKIM_STAT_OK)
				{
					return dkimf_libstatus(ctx, NULL,
					                       "dkim_resign()",
					                       status);
				}
			}
#endif /* _FFR_RESIGN */
		}
	}

	/* if requested, verify RFC5322-required headers (RFC5322 3.6) */
	if (conf->conf_reqhdrs)
	{
		_Bool ok = TRUE;

		/* exactly one From: */
		if (dkimf_findheader(dfc, "From", 0) == NULL ||
		    dkimf_findheader(dfc, "From", 1) != NULL)
			ok = FALSE;

		/* exactly one Date: */
		if (dkimf_findheader(dfc, "Date", 0) == NULL ||
		    dkimf_findheader(dfc, "Date", 1) != NULL)
			ok = FALSE;

		/* no more than one Reply-To: */
		if (dkimf_findheader(dfc, "Reply-To", 1) != NULL)
			ok = FALSE;

		/* no more than one To: */
		if (dkimf_findheader(dfc, "To", 1) != NULL)
			ok = FALSE;

		/* no more than one Cc: */
		if (dkimf_findheader(dfc, "Cc", 1) != NULL)
			ok = FALSE;

		/* no more than one Bcc: */
		if (dkimf_findheader(dfc, "Bcc", 1) != NULL)
			ok = FALSE;

		/* no more than one Message-Id: */
		if (dkimf_findheader(dfc, "Message-Id", 1) != NULL)
			ok = FALSE;

		/* no more than one In-Reply-To: */
		if (dkimf_findheader(dfc, "In-Reply-To", 1) != NULL)
			ok = FALSE;

		/* no more than one References: */
		if (dkimf_findheader(dfc, "References", 1) != NULL)
			ok = FALSE;

		/* no more than one Subject: */
		if (dkimf_findheader(dfc, "Subject", 1) != NULL)
			ok = FALSE;

		if (!ok)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_INFO,
				       "%s: RFC5322 header requirement error",
				       dfc->mctx_jobid);
			}

			dfc->mctx_addheader = TRUE;
			dfc->mctx_headeronly = TRUE;
			dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
			return SMFIS_CONTINUE;
		}
	}

#ifdef _FFR_IDENTITY_HEADER
	if (conf->conf_identityhdr != NULL)
		setidentity = TRUE;
#endif /* _FFR_IDENTITY_HEADER */

	if (dfc->mctx_srhead != NULL && setidentity)
	{
		u_char identity[MAXADDRESS + 1];
		_Bool idset = FALSE;

#ifdef _FFR_IDENTITY_HEADER
		if (conf->conf_identityhdr != NULL)
		{
			struct Header *hdr;
			u_char *iuser = NULL;
			u_char *idomain = NULL;

			hdr = dkimf_findheader(dfc, conf->conf_identityhdr, 0);
			if (hdr != NULL)
			{
				status = dkim_mail_parse(hdr->hdr_val,
				                         &iuser, &idomain);
				if (status == 0 && idomain != NULL)
				{
					snprintf((char *) identity,
					         sizeof identity,
						 "%s@%s",
						 iuser == NULL ? ""
					                       : (char *) iuser,
						 idomain);
					idset = TRUE;
				}
			}
		
			if (!idset && conf->conf_dolog)
			{
				syslog(LOG_INFO,
				       "%s: cannot find identity header %s",
				       dfc->mctx_jobid,
				       conf->conf_identityhdr);
			}
		}
#endif /* _FFR_IDENTITY_HEADER */
				
		if (!idset)
		{
			snprintf((char *) identity, sizeof identity, "@%s",
			         dfc->mctx_domain);
		}

		if (dfc->mctx_srhead != NULL)
		{
			struct signreq *sr;

			for (sr = dfc->mctx_srhead;
			     sr != NULL;
			     sr = sr->srq_next)
			{
				if (dkim_get_signer(sr->srq_dkim) == NULL)
				{
					dkim_set_signer(sr->srq_dkim,
					                identity);
				}
			}
		}
	}

	if (dfc->mctx_ltag && dfc->mctx_srhead != NULL)
	{
		struct signreq *sr;

		for (sr = dfc->mctx_srhead;
		     sr != NULL;
		     sr = sr->srq_next)
			dkim_setpartial(sr->srq_dkim, TRUE);
	}

#ifdef _FFR_VBR
	/* establish a VBR handle */
	dfc->mctx_vbr = vbr_init(NULL, NULL, NULL);
	if (dfc->mctx_vbr == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: can't create VBR context",
			       dfc->mctx_jobid);
		}
		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

# ifdef USE_UNBOUND
	dkimf_vbr_unbound_setup(dfc->mctx_vbr);
# endif /* USE_UNBOUND */

	if (conf->conf_vbr_trustedonly)
		vbr_options(dfc->mctx_vbr, VBR_OPT_TRUSTEDONLY);

	/* store the trusted certifiers */
	if (conf->conf_vbr_trusted != NULL)
		vbr_trustedcerts(dfc->mctx_vbr, conf->conf_vbr_trusted);

	if (vbr_dns_init(dfc->mctx_vbr) != 0)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: can't initialize VBR resolver",
			       dfc->mctx_jobid);
		}
		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	if (conf->conf_nslist != NULL)
	{
		status = vbr_dns_nslist(dfc->mctx_vbr, conf->conf_nslist);
		if (status != VBR_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: can't set VBR resolver list",
				       dfc->mctx_jobid);
			}
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	if (conf->conf_trustanchorpath != NULL)
	{
		if (access(conf->conf_trustanchorpath, R_OK) != 0)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: %s: access(): %s",
				       dfc->mctx_jobid,
				       conf->conf_trustanchorpath,
				       strerror(errno));
			}
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}

		status = vbr_dns_trustanchor(dfc->mctx_vbr,
		                             conf->conf_trustanchorpath);
		if (status != DKIM_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: can't set VBR trust anchor from %s",
				       dfc->mctx_jobid,
				       conf->conf_trustanchorpath);
			}
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	if (conf->conf_resolverconfig != NULL)
	{
		status = vbr_dns_config(dfc->mctx_vbr,
		                        conf->conf_resolverconfig);
		if (status != DKIM_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: can't set VBR resolver configuration",
				       dfc->mctx_jobid);
			}
			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	if (dfc->mctx_srhead != NULL)
	{
		Header newhdr;
		char header[DKIM_MAXHEADER + 1];

		/* set the sending domain */
		vbr_setdomain(dfc->mctx_vbr, dfc->mctx_domain);

		/* VBR-Type; get value from headers or use default */
		hdr = dkimf_findheader(dfc, VBRTYPEHEADER, 0);
		if (hdr != NULL)
		{
			dfc->mctx_vbrpurge = TRUE;
			vbr_type = hdr->hdr_val;
		}
		else
		{
			vbr_type = conf->conf_vbr_deftype;
		}

		/* X-VBR-Certifiers; get value from headers or use default */
		hdr = dkimf_findheader(dfc, VBRCERTHEADER, 0);
		if (hdr != NULL)
		{
			dfc->mctx_vbrpurge = TRUE;
			vbr_cert = hdr->hdr_val;
		}
		else
		{
			vbr_cert = conf->conf_vbr_defcert;
		}

		/* set message type and certifiers, and generate a header */
		if (vbr_type != NULL && vbr_cert != NULL)
		{
			memset(header, '\0', sizeof header);

			/* set the VBR transaction type */
			(void) vbr_settype(dfc->mctx_vbr, (u_char *) vbr_type);
	
			/* set the VBR certifier list */
			(void) vbr_setcert(dfc->mctx_vbr, (u_char *) vbr_cert);

			status = vbr_getheader(dfc->mctx_vbr,
			                       header, sizeof header);
			if (status != VBR_STAT_OK)
			{
				const char *err;

				err = vbr_geterror(dfc->mctx_vbr);

				syslog(LOG_ERR,
				       "%s: can't create VBR-Info header field%s%s",
				       dfc->mctx_jobid,
				       err == NULL ? "" : ": ",
				       err == NULL ? "" : err);
			}
			else
			{
				/* store it for addition in mlfi_eom() */
				dfc->mctx_vbrinfo = strdup(header);
				if (dfc->mctx_vbrinfo == NULL)
				{
					syslog(LOG_ERR, "%s: strdup(): %s",
					       dfc->mctx_jobid,
					       strerror(errno));
					dkimf_cleanup(ctx);
					return SMFIS_TEMPFAIL;
				}

				/* add it to header set so it gets signed */
				newhdr = (Header) malloc(sizeof(struct Header));
				if (newhdr == NULL)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR, "malloc(): %s",
						       strerror(errno));

						dkimf_cleanup(ctx);
						return SMFIS_TEMPFAIL;
					}
				}

				(void) memset(newhdr, '\0',
				              sizeof(struct Header));

				newhdr->hdr_hdr = strdup(VBR_INFOHEADER);
				newhdr->hdr_val = strdup(header);

				if (newhdr->hdr_hdr == NULL ||
				    newhdr->hdr_val == NULL)
				{
					syslog(LOG_ERR, "%s: strdup(): %s",
					       dfc->mctx_jobid,
					       strerror(errno));
					TRYFREE(newhdr->hdr_hdr);
					dkimf_cleanup(ctx);
					return SMFIS_TEMPFAIL;
				}

				newhdr->hdr_next = NULL;
				newhdr->hdr_prev = dfc->mctx_hqtail;

				if (dfc->mctx_hqhead == NULL)
					dfc->mctx_hqhead = newhdr;

				if (dfc->mctx_hqtail != NULL)
					dfc->mctx_hqtail->hdr_next = newhdr;

				dfc->mctx_hqtail = newhdr;
			}
		}
	}
#endif /* _FFR_VBR */

	/* run the headers */
	for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		if (dfc->mctx_tmpstr == NULL)
		{
			dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);
			if (dfc->mctx_tmpstr == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: dkimf_dstring_new() failed",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}
		}
		else
		{
			dkimf_dstring_blank(dfc->mctx_tmpstr);
		}

		/*
		**  Skip headers we know we're going to delete before
		**  signing here (e.g. identity header when set to remove).
		*/

		/*
		**  XXX -- may need to skip some/all Authentication-Results
		**  header fields here, especially in the re-signing case
		*/

#ifdef _FFR_IDENTITY_HEADER
		if (conf->conf_identityhdr != NULL &&
		    conf->conf_rmidentityhdr && 
		    dfc->mctx_srhead != NULL &&
		    strcasecmp(conf->conf_identityhdr, hdr->hdr_hdr) == 0)
			continue;
#endif /* _FFR_IDENTITY_HEADER */

		dkimf_dstring_copy(dfc->mctx_tmpstr, (u_char *) hdr->hdr_hdr);
		dkimf_dstring_cat1(dfc->mctx_tmpstr, ':');
		if (!cc->cctx_noleadspc)
			dkimf_dstring_cat1(dfc->mctx_tmpstr, ' ');

		last = '\0';

		/* do milter-ized continuation conversion */
		for (p = hdr->hdr_val; *p != '\0'; p++)
		{
			if (*p == '\n' && last != '\r')
				dkimf_dstring_cat1(dfc->mctx_tmpstr, '\r');

			dkimf_dstring_cat1(dfc->mctx_tmpstr, *p);

			last = *p;
		}

#ifdef _FFR_REPUTATION
		/* check for spam flag */
		if (conf->conf_repspamcheck != NULL &&
		    regexec(&conf->conf_repspamre, 
		            dkimf_dstring_get(dfc->mctx_tmpstr),
		            0, NULL, 0) == 0)
			dfc->mctx_spam = TRUE;
#endif /* _FFR_REPUTATION */

		if (dfc->mctx_srhead != NULL)
		{
			DKIM *dkim;

			status = dkimf_msr_header(dfc->mctx_srhead, &dkim,
				                  dkimf_dstring_get(dfc->mctx_tmpstr),
				                  dkimf_dstring_len(dfc->mctx_tmpstr));
			if (status != DKIM_STAT_OK)
			{
				ms = dkimf_libstatus(ctx, dkim,
				                     "dkim_header()", status);
				break;
			}
		}

		if (dfc->mctx_dkimv != NULL)
		{
			status = dkim_header(dfc->mctx_dkimv,
			                     (u_char *) dkimf_dstring_get(dfc->mctx_tmpstr),
			                     dkimf_dstring_len(dfc->mctx_tmpstr));

			if (status != DKIM_STAT_OK)
			{
				ms = dkimf_libstatus(ctx, dfc->mctx_dkimv,
				                     "dkim_header()", status);
			}
		}
	}

	/* return any error status from earlier */
	if (ms != SMFIS_CONTINUE)
		return ms;

	/* signal end of headers to libopendkim */
	lastdkim = NULL;
	status = DKIM_STAT_OK;
#ifdef _FFR_RESIGN
	if (dfc->mctx_srhead != NULL && !dfc->mctx_resign)
#else /* _FFR_RESIGN */
	if (dfc->mctx_srhead != NULL)
#endif /* _FFR_RESIGN */
		status = dkimf_msr_eoh(dfc->mctx_srhead, &lastdkim);
	if (status == DKIM_STAT_OK && dfc->mctx_dkimv != NULL)
	{
		(void) dkim_set_user_context(dfc->mctx_dkimv, ctx);
		lastdkim = dfc->mctx_dkimv;
		status = dkim_eoh(dfc->mctx_dkimv);
	}

#ifdef USE_LUA
	if (conf->conf_screenscript != NULL)
	{
		_Bool dofree = TRUE;
		struct dkimf_lua_script_result lres;

		memset(&lres, '\0', sizeof lres);

		status = dkimf_lua_screen_hook(ctx, conf->conf_screenfunc,
		                               conf->conf_screenfuncsz,
		                               "screen script", &lres,
		                               NULL, NULL);

		if (status != 0)
		{
			if (conf->conf_dolog)
			{
				if (lres.lrs_error == NULL)
				{
					dofree = FALSE;

					switch (status)
					{
					  case 2:
						lres.lrs_error = "processing error";
						break;

					  case 1:
						lres.lrs_error = "syntax error";
						break;

					  case -1:
						lres.lrs_error = "memory allocation error";
						break;

					  default:
						lres.lrs_error = "unknown error";
						break;
					}
				}

				syslog(LOG_ERR,
				       "%s: dkimf_lua_screen_hook() failed: %s",
				       dfc->mctx_jobid, lres.lrs_error);
			}

			if (dofree)
				free(lres.lrs_error);

			return SMFIS_TEMPFAIL;
		}
	}
#endif /* USE_LUA */

	switch (status)
	{
	  case DKIM_STAT_REVOKED:
		dfc->mctx_status = DKIMF_STATUS_REVOKED;
		dfc->mctx_addheader = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_BADSIG:
		dfc->mctx_status = DKIMF_STATUS_BAD;
		dfc->mctx_addheader = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_NOSIG:
		dfc->mctx_status = DKIMF_STATUS_NOSIGNATURE;
		if (conf->conf_alwaysaddar)
			dfc->mctx_addheader = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_NOKEY:
		dfc->mctx_status = DKIMF_STATUS_NOKEY;
		dfc->mctx_addheader = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_SYNTAX:
		dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		return SMFIS_CONTINUE;

	  /* XXX -- other codes? */

	  case DKIM_STAT_OK:
		return SMFIS_CONTINUE;

	  default:
		return dkimf_libstatus(ctx, lastdkim, "dkim_eoh()", status);
	}
}

/*
**  MLFI_BODY -- handler for an arbitrary body block
**
**  Parameters:
**  	ctx -- milter context
**  	bodyp -- body block
**  	bodylen -- amount of data available at bodyp
**
**  Return value:
**  	An SMFIS_* constant.
**
**  Description:
**  	This function reads the body chunks passed by the MTA and
**  	stores them for later wrapping, if needed.
*/

sfsistat
mlfi_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
	int status;
	DKIM *last;
	msgctx dfc;
	connctx cc;

	assert(ctx != NULL);
	assert(bodyp != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);

	/*
	**  No need to do anything if the body was empty.
	*/

	if (bodylen == 0)
		return SMFIS_CONTINUE;

#ifdef _FFR_REPUTATION
# ifdef USE_GNUTLS
	(void) gnutls_hash(dfc->mctx_hash, bodyp, bodylen);
# else /* USE_GNUTLS */
	SHA1_Update(&dfc->mctx_hash, bodyp, bodylen);
# endif /* USE_GNUTLS */
#endif /* _FFR_REPUTATION */

	/*
	**  Tell the filter to skip it if we don't care about the body.
	*/

	if (dfc->mctx_headeronly)
	{
#ifdef SMFIS_SKIP
		if (cc->cctx_milterv2)
			return SMFIS_SKIP;
		else
			return SMFIS_CONTINUE;
#else /* SMFIS_SKIP */
			return SMFIS_CONTINUE;
#endif /* SMFIS_SKIP */
	}

	last = NULL;
	status = DKIM_STAT_OK;
#ifdef _FFR_RESIGN
	if (dfc->mctx_srhead != NULL &&
	    (!dfc->mctx_resign || dfc->mctx_dkimv == NULL))
#else /* _FFR_RESIGN */
	if (dfc->mctx_srhead != NULL)
#endif /* _FFR_RESIGN */
	{
		status = dkimf_msr_body(dfc->mctx_srhead, &last,
		                        bodyp, bodylen);
	}
	if (status == DKIM_STAT_OK && dfc->mctx_dkimv != NULL)
	{
		last = dfc->mctx_dkimv;
		status = dkim_body(dfc->mctx_dkimv, bodyp, bodylen);
	}

	if (status != DKIM_STAT_OK)
		return dkimf_libstatus(ctx, last, "dkim_body()", status);

#ifdef SMFIS_SKIP
	if (dfc->mctx_srhead != NULL && cc->cctx_milterv2 &&
	    dkimf_msr_minbody(dfc->mctx_srhead) == 0)
			return SMFIS_SKIP;

	if (dfc->mctx_dkimv != NULL && cc->cctx_milterv2 &&
	    dkim_minbody(dfc->mctx_dkimv) == 0)
			return SMFIS_SKIP;
#endif /* SMFIS_SKIP */

	return SMFIS_CONTINUE;
}

/*
**  MLFI_EOM -- handler called at the end of the message; we can now decide
**              based on the configuration if and how to add the text
**              to this message, then release resources
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_eom(SMFICTX *ctx)
{
	_Bool testkey = FALSE;
	_Bool authorsig;
	int status = DKIM_STAT_OK;
	int c;
	sfsistat ret;
	connctx cc;
	msgctx dfc;
	DKIM *lastdkim = NULL;
	char *authservid;
	char *hostname;
	struct dkimf_config *conf;
	DKIM_SIGINFO *sig = NULL;
	Header hdr;
	unsigned char header[DKIM_MAXHEADER + 1];

	assert(ctx != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	dfc->mctx_eom = TRUE;

	/*
	**  If necessary, try again to get the job ID in case it came down
	**  later than expected (e.g. postfix).
	*/

	if (strcmp((char *) dfc->mctx_jobid, JOBIDUNKNOWN) == 0)
	{
		dfc->mctx_jobid = (u_char *) dkimf_getsymval(ctx, "i");
		if (dfc->mctx_jobid == NULL || dfc->mctx_jobid[0] == '\0')
		{
			if (no_i_whine && conf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "WARNING: symbol 'i' not available");
				no_i_whine = FALSE;
			}
			dfc->mctx_jobid = (u_char *) JOBIDUNKNOWN;
		}
	}

	/* get hostname; used in the X header and in new MIME boundaries */
	hostname = dkimf_getsymval(ctx, "j");
	if (hostname == NULL)
		hostname = HOSTUNKNOWN;

	/* select authserv-id to use when generating result headers */
	authservid = conf->conf_authservid;
	if (authservid == NULL)
		authservid = hostname;

	/* if this was totally malformed, add a header field and stop */
	if (dfc->mctx_headeronly)
	{
		/* allow for override */
		if (conf->conf_passmalformed)
			return SMFIS_ACCEPT;

		const char *ar;

		switch (dfc->mctx_status)
		{
		  case DKIMF_STATUS_BAD:
			ar = "fail";
			break;

		  case DKIMF_STATUS_NOKEY:
		  case DKIMF_STATUS_BADFORMAT:
			ar = "permerror";
			break;

		  case DKIMF_STATUS_NOSIGNATURE:
			ar = "none";
			break;

		  case DKIMF_STATUS_GOOD:
		  case DKIMF_STATUS_REVOKED:
		  case DKIMF_STATUS_PARTIAL:
		  case DKIMF_STATUS_VERIFYERR:
		  case DKIMF_STATUS_UNKNOWN:
		  default:
			assert(0);
			/* NOTREACHED */
		}

		snprintf(header, sizeof header, "%s; dkim=%s (%s)",
		         authservid, ar,
		         dkimf_lookup_inttostr(dfc->mctx_status,
		                               dkimf_statusstrings));

		if (dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
		                    (char *) header) == MI_FAILURE)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: %s header add failed",
				       dfc->mctx_jobid,
				       AUTHRESULTSHDR);
			}

			return SMFIS_TEMPFAIL;
		}

		return SMFIS_ACCEPT;
	}

	/* remove old signatures when signing */
	if (conf->conf_remsigs && dfc->mctx_srhead != NULL)
	{
		for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (strcasecmp(hdr->hdr_hdr, DKIM_SIGNHEADER) == 0)
			{
				if (dkimf_chgheader(ctx, hdr->hdr_hdr,
				                    0, NULL) != MI_SUCCESS)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_WARNING,
						       "failed to remove %s: header",
						       hdr->hdr_hdr);
					}
				}
			}
		}
	}

#ifdef _FFR_IDENTITY_HEADER
	/* remove identity header if such was requested when signing */
	if (conf->conf_rmidentityhdr && conf->conf_identityhdr != NULL &&
	    dfc->mctx_srhead != NULL)
	{
		struct Header *hdr;
		
		hdr = dkimf_findheader(dfc, conf->conf_identityhdr, 0);
		if (hdr != NULL)
		{
			if (dkimf_chgheader(ctx, conf->conf_identityhdr,
			                    0, NULL) != MI_SUCCESS)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_WARNING,
						"failed to remove %s: header",
						conf->conf_identityhdr);
				}
			}
		}
	}
#endif /* _FFR_IDENTITY_HEADER */
					
	/* log something if the message was multiply signed */
	if (dfc->mctx_dkimv != NULL && conf->conf_dolog)
	{
		int nsigs;
		DKIM_SIGINFO **sigs;

		lastdkim = dfc->mctx_dkimv;
		status = dkim_getsiglist(dfc->mctx_dkimv, &sigs, &nsigs);
		if (status == DKIM_STAT_OK && nsigs > 1)
		{
			u_char *d;

			if (dfc->mctx_tmpstr == NULL)
			{
				dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);

				if (dfc->mctx_tmpstr == NULL)
				{
					syslog(LOG_WARNING,
					       "%s: dkimf_dstring_new() failed",
					       dfc->mctx_jobid);

					return SMFIS_TEMPFAIL;
				}
			}
			else
			{
				dkimf_dstring_blank(dfc->mctx_tmpstr);
			}

			dkimf_dstring_cat(dfc->mctx_tmpstr, dfc->mctx_jobid);
			dkimf_dstring_cat(dfc->mctx_tmpstr,
			                  (u_char *) ": message has signatures from ");

			for (c = 0; c < nsigs; c++)
			{
				if (c != 0)
				{
					dkimf_dstring_cat(dfc->mctx_tmpstr,
					                  (u_char *) ", ");
				}

				d = dkim_sig_getdomain(sigs[c]);
				if (d == NULL)
					d = (u_char *) NULLDOMAIN;

				dkimf_dstring_cat(dfc->mctx_tmpstr, d);
			}

			syslog(LOG_INFO, "%s",
			       dkimf_dstring_get(dfc->mctx_tmpstr));
		}
	}

	/*
	**  Remove all Authentication-Results: headers as per configuration
	**  options when verifying.
	*/

	if (dfc->mctx_dkimv != NULL && !conf->conf_keepar)
	{
		struct authres *ares;

		ares = (struct authres *) malloc(sizeof(struct authres));
		if (ares == NULL)
		{
			syslog(LOG_WARNING,
			       "%s: malloc(): %s", dfc->mctx_jobid,
			       strerror(errno));

			return SMFIS_TEMPFAIL;
		}

		c = 0;
		for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			memset(ares, '\0', sizeof(struct authres));

			if (strcasecmp(hdr->hdr_hdr, AUTHRESULTSHDR) == 0)
			{
				_Bool dkimres = FALSE;
				_Bool hostmatch = FALSE;
				int arstat;
				char *slash;

				/* remember index */
				c++;

				/* parse the header */
				arstat = ares_parse((u_char *) hdr->hdr_val,
				                    ares);
				if (arstat == -1)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_WARNING,
						       "%s: failed to parse %s: header field",
						       dfc->mctx_jobid,
						       hdr->hdr_hdr);
					}

					continue;
				}

				/* method match? */
				if (conf->conf_remarall)
				{
					dkimres = TRUE;
				}
				else
				{
					int d;

					for (d = 0; d < ares->ares_count; d++)
					{
						if (ares->ares_result[d].result_method == ARES_METHOD_DKIM)
							dkimres = TRUE;
					}
				}

				/* hostname match? */
				slash = strchr((char *) ares->ares_host, '/');
				if (slash != NULL)
					*slash = '\0';
					
				if (conf->conf_remardb != NULL)
				{
					status = dkimf_db_get(conf->conf_remardb,
					                      ares->ares_host,
					                      0, NULL, 0,
					                      &hostmatch);
					if (status != 0 && dolog)
					{
						dkimf_db_error(conf->conf_remardb,
						               (char *) ares->ares_host);
					}
				}
				else
				{
					if (strcasecmp(authservid,
					               (char *) ares->ares_host) == 0)
						hostmatch = TRUE;
				}

				/* delete if we found both */
				if (dkimres && hostmatch)
				{
					if (dkimf_chgheader(ctx, hdr->hdr_hdr,
					                    c,
					                    NULL) != MI_SUCCESS)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_WARNING,
							       "failed to remove %s: header",
							       hdr->hdr_hdr);
						}
					}
				}
			}
		}

		free(ares);
	}

	/* complete verification if started */
	if (dfc->mctx_dkimv != NULL)
	{
		/*
		**  Signal end-of-message to DKIM
		*/

		status = dkim_eom(dfc->mctx_dkimv, &testkey);
		lastdkim = dfc->mctx_dkimv;

		if (conf->conf_logresults && conf->conf_dolog)
		{
			int c;
			int nsigs;
			DKIM_STAT lstatus;
			DKIM_SIGINFO **sigs;

			if (dfc->mctx_tmpstr == NULL)
			{
				dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ,
				                                     0);

				if (dfc->mctx_tmpstr == NULL)
				{
					syslog(LOG_WARNING,
					       "%s: dkimf_dstring_new() failed",
					       dfc->mctx_jobid);

					return SMFIS_TEMPFAIL;
				}
			}
			else
			{
				dkimf_dstring_blank(dfc->mctx_tmpstr);
			}

			lstatus = dkim_getsiglist(dfc->mctx_dkimv,
			                          &sigs, &nsigs);

			if (lstatus == DKIM_STAT_OK)
			{
				DKIM_SIGERROR err;
				size_t len;
				const char *domain;
				const char *selector;
				const char *errstr;
				char substr[BUFRSZ];

				for (c = 0; c < nsigs; c++)
				{
					domain = dkim_sig_getdomain(sigs[c]);
					selector = dkim_sig_getselector(sigs[c]);
					err = dkim_sig_geterror(sigs[c]);
					errstr = dkim_sig_geterrorstr(err);

					memset(substr, '\0', sizeof substr);
					len = sizeof substr;

					lstatus = dkim_get_sigsubstring(dfc->mctx_dkimv,
					                                sigs[c],
					                                substr,
					                                &len);

					if (lstatus == DKIM_STAT_OK &&
					    domain != NULL &&
					    selector != NULL &&
					    errstr != NULL)
					{
						if (dkimf_dstring_len(dfc->mctx_tmpstr) > 0)
						{
							dkimf_dstring_catn(dfc->mctx_tmpstr,
							                   "; ",
							                   2);
						}

						dkimf_dstring_printf(dfc->mctx_tmpstr,
						                     "signature=%s domain=%s selector=%s result=\"%s\"",
						                     substr,
						                     domain,
						                     selector,
						                     errstr);
					}
				}

				if (dkimf_dstring_len(dfc->mctx_tmpstr) > 0)
				{
					syslog(LOG_INFO, "%s: %s",
					       dfc->mctx_jobid,
					       dkimf_dstring_get(dfc->mctx_tmpstr));
				}
			}
		}

		switch (status)
		{
		  case DKIM_STAT_OK:
			if (dkimf_findheader(dfc, DKIM_SIGNHEADER, 0) != NULL)
			{
				if (conf->conf_dolog_success)
				{
					syslog(LOG_INFO,
					       "%s: DKIM verification successful",
					       dfc->mctx_jobid);
				}

				dfc->mctx_addheader = TRUE;
				dfc->mctx_status = DKIMF_STATUS_GOOD;
			}
			break;

		  case DKIM_STAT_CANTVRFY:
			dfc->mctx_addheader = TRUE;
			dfc->mctx_status = DKIMF_STATUS_VERIFYERR;
			break;

		  case DKIM_STAT_BADSIG:
			dfc->mctx_addheader = TRUE;
			dfc->mctx_status = DKIMF_STATUS_BAD;
			break;

		  case DKIM_STAT_NOSIG:
			if (conf->conf_alwaysaddar)
			{
				dfc->mctx_addheader = TRUE;
				dfc->mctx_status = DKIMF_STATUS_NOSIGNATURE;
			}
			break;

		  case DKIM_STAT_NOKEY:
			dfc->mctx_addheader = TRUE;
			dfc->mctx_status = DKIMF_STATUS_NOKEY;
			break;

		  case DKIM_STAT_REVOKED:
			dfc->mctx_addheader = TRUE;
			dfc->mctx_status = DKIMF_STATUS_REVOKED;
			break;

		  default:
			if (conf->conf_dolog)
			{
				lastdkim = dfc->mctx_dkimv;
				sig = dkim_getsignature(dfc->mctx_dkimv);
				dkimf_log_ssl_errors(lastdkim, sig,
				                     (char *) dfc->mctx_jobid);
			}

			status = dkimf_libstatus(ctx, dfc->mctx_dkimv,
			                         "dkim_eom()", status);

#ifdef SMFIF_QUARANTINE
			if (dfc->mctx_capture)
			{
				if (dkimf_quarantine(ctx,
				                     "capture requested") != MI_SUCCESS)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: smfi_quarantine() failed",
						       dfc->mctx_jobid);
					}
				}

				status = SMFIS_ACCEPT;
			}
#endif /* ! SMFIF_QUARANTINE */
			break;
		}

		authorsig = dkimf_authorsigok(dfc);

		if (conf->conf_diagdir != NULL &&
		    dfc->mctx_status == DKIMF_STATUS_BAD)
		{
			int nhdrs;
			dkim_canon_t canon;
			u_char *ohdrs[MAXHDRCNT];

			nhdrs = MAXHDRCNT;
			memset(ohdrs, '\0', sizeof ohdrs);

			sig = dkim_getsignature(dfc->mctx_dkimv);

			(void) dkim_sig_getcanons(sig, &canon, NULL);

			status = dkim_ohdrs(dfc->mctx_dkimv, sig,
			                    ohdrs, &nhdrs);
			if (status == DKIM_STAT_OK && nhdrs > 0)
			{
				FILE *f;
				char dpath[MAXPATHLEN + 1];

				snprintf(dpath, sizeof dpath, "%s/%s",
				         conf->conf_diagdir, dfc->mctx_jobid);

				f = fopen(dpath, "w");
				if (f == NULL)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: %s: fopen(): %s",
						       dfc->mctx_jobid,
						       dpath, strerror(errno));
					}
				}
				else
				{
					int c;
#ifdef _FFR_DIFFHEADERS
					int ndiffs;
					struct dkim_hdrdiff *diffs;
#endif /* _FFR_DIFFHEADERS */
					struct Header *hdr;

					fprintf(f, "z tag headers:\n\n");

					for (c = 0; c < nhdrs; c++)
						fprintf(f, "%s\n", ohdrs[c]);

					fprintf(f, "--------------------\n\n");
					fprintf(f, "Received headers:\n\n");

					for (hdr = dfc->mctx_hqhead;
					     hdr != NULL;
					     hdr = hdr->hdr_next)
					{
						fprintf(f, "%s:%s%s\n",
						        hdr->hdr_hdr,
						        cc->cctx_noleadspc ? ""
						                           : " ",
						        hdr->hdr_val);
					}

#ifdef _FFR_DIFFHEADERS
					/* XXX -- make the "5" configurable */
					status = dkim_diffheaders(dfc->mctx_dkimv,
					                          canon,
					                          5,
					                          (char **) ohdrs,
					                          nhdrs,
					                          &diffs,
					                          &ndiffs);

					if (status == DKIM_STAT_OK &&
					    diffs != NULL && ndiffs > 0)
					{
						fprintf(f, "--------------------\n\n");
						fprintf(f, "Munging detected:\n\n");

						for (c = 0; c < ndiffs; c++)
						{
							fprintf(f,
							        "-%s\n+%s\n\n",
							        diffs[c].hd_old,
							        diffs[c].hd_new);
						}

						if (ndiffs > 0)
							free(diffs);
					}
#endif /* _FFR_DIFFHEADERS */

					fclose(f);
				}
			}
		}	

		if (dfc->mctx_status == DKIMF_STATUS_GOOD)
		{
			if (conf->conf_sigmin > 0)
			{
				ssize_t canonlen;
				ssize_t bodylen;

				sig = dkim_getsignature(dfc->mctx_dkimv);
				(void) dkim_sig_getcanonlen(dfc->mctx_dkimv,
				                            sig, &bodylen,
				                            &canonlen, NULL);

				if (conf->conf_sigmintype == SIGMIN_PERCENT)
				{
					size_t signpct;

					signpct = (100 * canonlen) / bodylen;

					if (signpct < conf->conf_sigmin)
						dfc->mctx_status = DKIMF_STATUS_PARTIAL;
				}
				else if (conf->conf_sigmintype == SIGMIN_MAXADD)
				{
					if (canonlen + conf->conf_sigmin < bodylen)
						dfc->mctx_status = DKIMF_STATUS_PARTIAL;
				}
				else
				{
					size_t required;

					required = MIN(conf->conf_sigmin,
					               bodylen);

					if (canonlen < required)
						dfc->mctx_status = DKIMF_STATUS_PARTIAL;
				}
			}
		}

#ifdef USE_UNBOUND
		sig = dkim_getsignature(dfc->mctx_dkimv);
		if (sig != NULL)
			dfc->mctx_dnssec_key = dkim_sig_getdnssec(sig);
#endif /* USE_UNBOUND */

#ifdef _FFR_ATPS
		if (dfc->mctx_status != DKIMF_STATUS_UNKNOWN && !authorsig)
		{
			int nsigs;
			dkim_atps_t atps = DKIM_ATPS_UNKNOWN;
			DKIM_SIGINFO **sigs;

			status = dkim_getsiglist(dfc->mctx_dkimv, &sigs, &nsigs);
			if (status == DKIM_STAT_OK)
			{
				for (c = 0;
				     c < nsigs && atps != DKIM_ATPS_FOUND;
				     c++)
				{
					if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) != 0 &&
					    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH &&
					    strcasecmp(dkim_sig_getdomain(sigs[c]),
					               dfc->mctx_domain) != 0)
					{
						status = dkim_atps_check(dfc->mctx_dkimv,
						                         sigs[c],
						                         NULL,
						                         &atps);

						if (status != DKIM_STAT_OK)
							break;
					}
				}

				dfc->mctx_atps = atps;
			}
		}
#endif /* _FFR_ATPS */

#ifdef _FFR_STATS
		if (conf->conf_statspath != NULL && dfc->mctx_dkimv != NULL)
		{
# ifdef USE_LUA
#  ifdef _FFR_STATSEXT
			if (conf->conf_statsscript != NULL)
			{
				_Bool dofree = TRUE;
				struct dkimf_lua_script_result lres;

				memset(&lres, '\0', sizeof lres);

				status = dkimf_lua_stats_hook(ctx,
				                              conf->conf_statsfunc,
				                              conf->conf_statsfuncsz,
				                              "stats script",
				                              &lres,
				                              NULL, NULL);

				if (status != 0)
				{
					if (conf->conf_dolog)
					{
						if (lres.lrs_error == NULL)
						{
							dofree = FALSE;

							switch (status)
							{
							  case 2:
								lres.lrs_error = "processing error";
								break;

							  case 1:
								lres.lrs_error = "syntax error";
								break;

							  case -1:
								lres.lrs_error = "memory allocation error";
								break;

							  default:
								lres.lrs_error = "unknown error";
								break;
							}
						}

						syslog(LOG_ERR,
						       "%s: dkimf_lua_stats_hook() failed: %s",
						       dfc->mctx_jobid,
						       lres.lrs_error);
					}

					if (dofree)
						free(lres.lrs_error);

					return SMFIS_TEMPFAIL;
				}
			}
#  endif /* _FFR_STATSEXT */
# endif /* USE_LUA */

			if (dkimf_stats_record(conf->conf_statspath,
			                       dfc->mctx_jobid,
			                       conf->conf_reporthost,
			                       conf->conf_reportprefix,
			                       dfc->mctx_hqhead,
			                       dfc->mctx_dkimv,
# ifdef _FFR_STATSEXT
			                       dfc->mctx_statsext,
# endif /* _FFR_STATSEXT */
# ifdef _FFR_ATPS
			                       dfc->mctx_atps,
# else /* _FFR_ATPS */
			                       -1,
# endif /* _FFR_ATPS */
# ifdef _FFR_REPUTATION
			                       dfc->mctx_spam,
# else /* _FFR_REPUTATION */
			                       -1,
# endif /* _FFR_REPUTATION */
			                       (struct sockaddr *) &cc->cctx_ip) != 0)
			{
				if (dolog)
				{
					syslog(LOG_WARNING,
					       "statistics recording failed");
				}
			}
		}
#endif /* _FFR_STATS */

#ifdef _FFR_REPRRD
		if (dfc->mctx_dkimv != NULL && conf->conf_reprrd != NULL)
		{
			DKIM_SIGINFO **sigs;
			int nsigs;

			status = dkim_getsiglist(dfc->mctx_dkimv,
			                         &sigs, &nsigs);

			if (status == DKIM_STAT_OK)
			{
				int c;
				int ret;
				const char *cd;
				const char *domain = NULL;

				for (c = 0; c < nsigs && domain == NULL; c++)
				{
					if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 ||
					    (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_TESTKEY) != 0 ||
					     dkim_sig_getbh(sigs[c]) != DKIM_SIGBH_MATCH)
						continue;

					cd = dkim_sig_getdomain(sigs[c]);

					ret = 0;

					status = reprrd_query(conf->conf_reprrd,
					                      cd,
					                      REPRRD_TYPE_MESSAGES,
					                      &ret, NULL, 0);
					if (status == 0 && ret == 0)
					{
						status = reprrd_query(conf->conf_reprrd,
						                      cd,
						                      REPRRD_TYPE_SPAM,
						                      &ret,
						                      NULL, 0);
					}

					if (status == 0 && ret == 0)
					{
						status = reprrd_query(conf->conf_reprrd,
						                      cd,
						                      REPRRD_TYPE_LIMIT,
						                      &ret,
						                      NULL, 0);
					}

					if (status == 0)
					{
						if (ret == 1)
						{
							domain = cd;
							break;
						}
						else if (conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: allowed by reputation of %s",
							       dfc->mctx_jobid,
							       cd);
						}
					}
					else if (status != REPRRD_STAT_NODATA)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: reputation query for \"%s\" failed (%d)",
							       dfc->mctx_jobid,
							       cd, status);
						}

						return dkimf_miltercode(ctx,
						                        conf->conf_handling.hndl_reperr,
						                        NULL);
					}
					else if (conf->conf_dolog)
					{
						syslog(LOG_NOTICE,
						       "%s: no reputation data available for \"%s\"",
						       dfc->mctx_jobid, cd);
					}
				}

				if (domain == NULL)
				{
					cd = "unsigned";

					status = reprrd_query(conf->conf_reprrd,
					                      cd,
					                      REPRRD_TYPE_MESSAGES,
					                      &ret, NULL, 0);
					if (status == 0 && ret == 0)
					{
						status = reprrd_query(conf->conf_reprrd,
						                      cd,
						                      REPRRD_TYPE_SPAM,
						                      &ret,
						                      NULL, 0);
					}

					if (status == 0 && ret == 0)
					{
						status = reprrd_query(conf->conf_reprrd,
						                      cd,
						                      REPRRD_TYPE_LIMIT,
						                      &ret,
						                      NULL, 0);
					}

					if (status == 1)
					{
						domain = "NULL domain";
					}
					else if (status == -1)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: reputation query for NULL domain failed (%d)",
							       dfc->mctx_jobid,
							       status);
						}

						return dkimf_miltercode(ctx,
						                        conf->conf_handling.hndl_reperr,
						                        NULL);
					}
				}

				if (domain != NULL)
				{
					if (dolog)
					{
						syslog(LOG_NOTICE,
						       "%s: %sblocked by reputation of %s",
						       dfc->mctx_jobid,
						       conf->conf_reptest ? "would be " : "",
						       domain);
					}

					if (!conf->conf_reptest)
					{
						if (dkimf_setreply(ctx,
						                   REPDENYSMTP,
						                   REPDENYESC,
						                   REPDENYTXT) != MI_SUCCESS &&
						    conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: smfi_setreply() failed",
							       dfc->mctx_jobid);
						}

						dkimf_cleanup(ctx);
						return SMFIS_TEMPFAIL;
					}
				}
			}
		}
#endif /* _FFR_REPRRD */

#ifdef _FFR_REPUTATION
		if (dfc->mctx_dkimv != NULL && conf->conf_rep != NULL &&
		    !dfc->mctx_internal)
		{
			float ratio;
			unsigned long count;
			unsigned long limit;
			unsigned long spam;
			DKIM_SIGINFO **sigs;
			int nsigs;

			status = dkim_getsiglist(dfc->mctx_dkimv,
			                         &sigs, &nsigs);

			if (status == DKIM_STAT_OK)
			{
				int c;
				_Bool checked = FALSE;
				const char *cd;
				const char *domain = NULL;
				unsigned char digest[SHA_DIGEST_LENGTH];
				char errbuf[BUFRSZ + 1];

# ifdef USE_GNUTLS
				(void) gnutls_hash_deinit(dfc->mctx_hash, digest);
# else /* USE_GNUTLS */
				SHA1_Final(digest, &dfc->mctx_hash);
# endif /* USE_GNUTLS */

				for (c = 0; c < nsigs; c++)
				{
					if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 ||
					    (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_TESTKEY) != 0 ||
					    dkim_sig_getbh(sigs[c]) != DKIM_SIGBH_MATCH)
						continue;

					checked = TRUE;

					cd = dkim_sig_getdomain(sigs[c]);

					status = dkimf_rep_check(conf->conf_rep,
					                         sigs[c],
					                         dfc->mctx_spam,
					                         digest,
					                         SHA_DIGEST_LENGTH,
					                         &limit,
					                         &ratio,
					                         &count,
					                         &spam,
					                         errbuf,
					                         sizeof errbuf);

					if (status == 1)
					{
						domain = cd;
						break;
					}
					else if (status == -1)
					{
						if (conf->conf_dolog)
						{
							cd = dkim_sig_getdomain(sigs[c]);
							syslog(LOG_NOTICE,
							       "%s: reputation query for \"%s\" failed: %s",
							       dfc->mctx_jobid,
							       cd, errbuf);
						}

						return dkimf_miltercode(ctx,
						                        conf->conf_handling.hndl_reperr,
						                        NULL);
					}
					else if (conf->conf_repverbose &&
					         conf->conf_dolog)
					{
						if (status == 2)
						{
							syslog(LOG_NOTICE,
							       "%s: no reputation data available for \"%s\"",
							       dfc->mctx_jobid,
							       cd);
						}
						else
						{
							syslog(LOG_INFO,
							       "%s: allowed by reputation of %s (%f, count %lu, spam %lu, limit %lu)",
							       dfc->mctx_jobid,
							       cd, ratio,
							       count,
						               spam, limit);
						}
					}
				}

				if (domain == NULL && !checked)
				{
					status = dkimf_rep_check(conf->conf_rep,
					                         NULL,
					                         dfc->mctx_spam,
					                         digest,
					                         SHA_DIGEST_LENGTH,
					                         &limit,
					                         &ratio,
					                         &count,
					                         &spam,
					                         errbuf,
					                         sizeof errbuf);

					if (status == 1)
					{
						domain = "NULL domain";
					}
					else if (status == -1)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: reputation query for NULL domain failed: %s",
							       dfc->mctx_jobid,
							       errbuf);
						}

						return dkimf_miltercode(ctx,
						                        conf->conf_handling.hndl_reperr,
						                        NULL);
					}
					else if (conf->conf_repverbose &&
					         conf->conf_dolog)
					{
						if (status == 2)
						{
							syslog(LOG_NOTICE,
							       "%s: no reputation data available for NULL domain",
							       dfc->mctx_jobid);
						}
						else
						{
							syslog(LOG_INFO,
							       "%s: allowed by reputation of NULL domain (%f, count %lu, spam %lu, limit %lu)",
							       dfc->mctx_jobid,
							       ratio,
							       count,
						               spam, limit);
						}
					}
				}

				if (domain != NULL)
				{
					if (dolog)
					{
						syslog(LOG_NOTICE,
						       "%s: %sblocked by reputation of %s (%f, count %lu, spam %lu, limit %lu)",
						       dfc->mctx_jobid,
						       conf->conf_reptest ? "would be " : "",
						       domain, ratio, count,
					               spam, limit);
					}

					if (!conf->conf_reptest)
					{
						if (dkimf_setreply(ctx,
						                   REPDENYSMTP,
						                   REPDENYESC,
						                   REPDENYTXT) != MI_SUCCESS &&
						    conf->conf_dolog)
						{
							syslog(LOG_NOTICE,
							       "%s: smfi_setreply() failed",
							       dfc->mctx_jobid);
						}

						dkimf_cleanup(ctx);
						return SMFIS_TEMPFAIL;
					}
				}
			}
		}
#endif /* _FFR_REPUTATION */

		if (dfc->mctx_addheader)
		{
			u_char val[MAXADDRESS + 1];

			/*
			**  Record DKIM and ADSP results in an
			**  Authentication-Results: header field.
			*/

			memset(val, '\0', sizeof val);
			memset(header, '\0', sizeof header);

			snprintf((char *) header, sizeof header, "%s%s",
		        	 cc->cctx_noleadspc ? " " : "",
		        	 authservid);

			if (conf->conf_authservidwithjobid &&
			    dfc->mctx_jobid != NULL)
			{
				strlcat((char *) header, "/", sizeof header);
				strlcat((char *) header,
				        (char *) dfc->mctx_jobid,
				        sizeof header);
			}

			strlcat((char *) header, ";", sizeof header);
			strlcat((char *) header, DELIMITER, sizeof header);

			if (dfc->mctx_status == DKIMF_STATUS_GOOD ||
			    dfc->mctx_status == DKIMF_STATUS_BAD ||
			    dfc->mctx_status == DKIMF_STATUS_REVOKED ||
			    dfc->mctx_status == DKIMF_STATUS_PARTIAL ||
			    dfc->mctx_status == DKIMF_STATUS_NOKEY ||
			    dfc->mctx_status == DKIMF_STATUS_VERIFYERR)
			{
				dkimf_ar_all_sigs(header, sizeof header,
				                  dfc->mctx_dkimv,
				                  conf, &dfc->mctx_status);
			}
			else if (dfc->mctx_status == DKIMF_STATUS_NOSIGNATURE)
			{
				strlcat((char *) header, "dkim=none",
				        sizeof header);
			}

#ifdef _FFR_ATPS
			strlcat((char *) header, ";", sizeof header);
			strlcat((char *) header, DELIMITER,
			        sizeof header);

			strlcat((char *) header, "dkim-atps=",
			        sizeof header);

			switch (dfc->mctx_atps)
			{
			  case DKIM_ATPS_UNKNOWN:
				strlcat((char *) header, "neutral",
				        sizeof header);
				break;

			  case DKIM_ATPS_NOTFOUND:
				strlcat((char *) header, "fail",
				        sizeof header);
				break;

			  case DKIM_ATPS_FOUND:
				strlcat((char *) header, "pass",
				        sizeof header);
				break;

			  default:
				assert(0);
			}
#endif /* _FFR_ATPS */

			/* if we generated either, pretty it up */
			if (header[0] != '\0')
			{
				_Bool first;
				int len;
				char *p;
				char *last;
				char tmphdr[DKIM_MAXHEADER + 1];

				c = sizeof AUTHRESULTSHDR + 2;
				first = TRUE;
				memset(tmphdr, '\0', sizeof tmphdr);

				for (p = strtok_r((char *) header,
				                  DELIMITER, &last);
				     p != NULL;
				     p = strtok_r(NULL, DELIMITER,
				                  &last))
				{
					len = strlen(p);

					if (!first)
					{
						if (c + len >= DKIM_HDRMARGIN)
						{
							strlcat(tmphdr,
							        "\n\t",
							        sizeof tmphdr);
							c = 8;
						}
						else
						{
							strlcat(tmphdr,
							        " ",
							        sizeof tmphdr);
						}
					}

					strlcat(tmphdr, p,
					        sizeof tmphdr);
					first = FALSE;
					c += len;
				}

				strlcpy((char *) dfc->mctx_dkimar,
				        tmphdr,
				        sizeof dfc->mctx_dkimar);

				dkimf_add_ar_fields(dfc, conf, ctx);

#ifdef _FFR_RESIGN
				if (dfc->mctx_resign)
				{
					snprintf(header, sizeof header,
					         "%s: %s",
					         AUTHRESULTSHDR,
					         dfc->mctx_dkimar);

					status = dkimf_msr_header(dfc->mctx_srhead,
					                          &lastdkim,
					                          header,
					                          strlen(header));
					if (status != DKIM_STAT_OK)
					{
						return dkimf_libstatus(ctx,
						                       lastdkim,
						                       "dkim_header()",
						                       status);
					}

					status = dkimf_msr_eoh(dfc->mctx_srhead,
					                       &lastdkim);

					if (status != DKIM_STAT_OK)
					{
						return dkimf_libstatus(ctx,
						                       lastdkim,
						                       "dkim_eoh()",
						                       status);
					}
				}
#endif /* _FFR_RESIGN */
			}
		}

#ifdef _FFR_RATE_LIMIT
		/* enact rate limiting */
		if (conf->conf_ratelimitdb != NULL &&
		    conf->conf_flowdatadb != NULL)
		{
			int exceeded = 0;
			int nvalid = 0;
			int nsigs = 0;
			unsigned int limit;
			DKIM_SIGINFO **sigs;

			if (dkim_getsiglist(dfc->mctx_dkimv, &sigs,
			                    &nsigs) == DKIM_STAT_OK)
			{
				for (c = 0; c < nsigs; c++)
				{
					if ((dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) == 0 &&
					    dkim_sig_getbh(sigs[c]) != DKIM_SIGBH_MATCH)
						continue;

					nvalid++;

					if (dkimf_rate_check(dkim_sig_getdomain(sigs[c]),
					                     conf->conf_ratelimitdb,
					                     conf->conf_flowdatadb,
					                     conf->conf_flowfactor,
					                     conf->conf_flowdatattl,
					                     &limit) == 1)
					{
						exceeded++;

						if (conf->conf_dolog)
						{
							syslog(LOG_ERR,
							       "%s: rate limit for '%s' (%u) exceeded",
							       dfc->mctx_jobid,
							       dkim_sig_getdomain(sigs[c]),
							       limit);
						}
					}
				}
			}

			if (nvalid == 0)
			{
				if (dkimf_rate_check(NULL,
				                     conf->conf_ratelimitdb,
				                     conf->conf_flowdatadb,
				                     conf->conf_flowfactor,
				                     conf->conf_flowdatattl,
				                     &limit) == 1)
				{
					exceeded++;

					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: rate limit for unsigned mail (%u) exceeded",
						       dfc->mctx_jobid,
						       limit);
					}
				}
			}

			if (exceeded > 0)
				return SMFIS_TEMPFAIL;
		}
#endif /* _FFR_RATE_LIMIT */

		/* send an ARF message for DKIM? */
		if (dfc->mctx_status == DKIMF_STATUS_BAD &&
		    conf->conf_sendreports)
			dkimf_sigreport(cc, conf, hostname);

#ifdef _FFR_VBR
	    	if (dkimf_valid_vbr(dfc))
		{
			_Bool add_vbr_header = FALSE;
			_Bool vbr_validsig = FALSE;
			VBR_STAT vbr_status = VBR_STAT_OK;
			int c;
			int nsigs;
			char *vbr_result;
			char *vbr_domain;
			char *vbr_certifier;
			char *vbr_vouchers;
			char *vbr_type;
			char *p;
			char *sctx;
			char *eq;
			u_char *param;
			u_char *value;
			DKIM_SIGINFO **sigs;
			Header vbr_header;
			char tmp[DKIM_MAXHEADER + 1];

			for (c = 0; ; c++)
			{
				vbr_header = dkimf_findheader(dfc,
				                              VBR_INFOHEADER,
				                              c);
				if (vbr_header == NULL)
					break;

				vbr_result = "none";
				vbr_domain = NULL;
				vbr_certifier = NULL;
				vbr_vouchers = NULL;
				vbr_type = NULL;
	
				/* break out the VBR-Info header contents */
				strlcpy(tmp, vbr_header->hdr_val, sizeof tmp);
				for (p = strtok_r(tmp, ";", &sctx);
				     p != NULL;
				     p = strtok_r(NULL, ";", &sctx))
				{
					eq = strchr(p, '=');
					if (eq == NULL)
						continue;
					*eq = '\0';

					for (param = (u_char *) p;
					     *param != '\0';
					     param++)
					{
						if (!(isascii(*param) &&
						      isspace(*param)))
							break;
					}
					dkimf_trimspaces(param);

					for (value = (u_char *) eq + 1;
					     *value != '\0';
					     value++)
					{
						if (!(isascii(*value) &&
						      isspace(*value)))
							break;
					}
					dkimf_trimspaces(value);

					if (strcasecmp((char *) param,
					               "md") == 0)
					{
						vbr_domain = (char *) value;
					}
					else if (strcasecmp((char *) param,
					                    "mc") == 0)
					{
						vbr_type = (char *) value;
					}
					else if (strcasecmp((char *) param,
					                    "mv") == 0)
					{
						vbr_vouchers = (char *) value;
					}
				}
			
				/* confirm a valid signature was there */
				if (dfc->mctx_dkimv != NULL &&
				    dkim_getsiglist(dfc->mctx_dkimv,
				                    &sigs,
				                    &nsigs) == DKIM_STAT_OK)
				{
					u_char *d;

					for (c = 0; c < nsigs; c++)
					{
						d = dkim_sig_getdomain(sigs[c]);
						if (strcasecmp((char *) d,
						               vbr_domain) == 0 &&
						    (dkim_sig_getflags(sigs[c]) & DKIM_SIGFLAG_PASSED) != 0 &&
						    dkim_sig_getbh(sigs[c]) == DKIM_SIGBH_MATCH)
						{
							vbr_validsig = TRUE;
							break;
						}
					}
				}
				
				if (vbr_validsig)
				{
					/* use accessors to set parsed values */
					vbr_setcert(dfc->mctx_vbr,
					            (u_char *) vbr_vouchers);
					vbr_settype(dfc->mctx_vbr,
					            (u_char *) vbr_type);
					vbr_setdomain(dfc->mctx_vbr,
					              (u_char *) vbr_domain);
		
					/* attempt the query */
					vbr_status = vbr_query(dfc->mctx_vbr,
					                       (u_char **) &vbr_result,
					                       (u_char **) &vbr_certifier);
				}

				switch (vbr_status)
				{
				  case VBR_STAT_DNSERROR:
					if (conf->conf_dolog)
					{
						const char *err;

						err = (const char *) vbr_geterror(dfc->mctx_vbr);

						syslog(LOG_NOTICE,
						       "%s: can't verify VBR information%s%s",
						       dfc->mctx_jobid,
						       err == NULL ? "" : ": ",
						       err == NULL ? "" : err);
					}

					add_vbr_header = TRUE;

					vbr_result = "temperror";
					break;

				  case VBR_STAT_INVALID:
				  case VBR_STAT_NORESOURCE:
					if (conf->conf_dolog)
					{
						const char *err;

						err = (const char *) vbr_geterror(dfc->mctx_vbr);

						syslog(LOG_NOTICE,
						       "%s: error handling VBR information%s%s",
						       dfc->mctx_jobid,
						       err == NULL ? "" : ": ",
						       err == NULL ? "" : err);
					}

					add_vbr_header = TRUE;

					if (vbr_status == VBR_STAT_INVALID)
						vbr_result = "temperror";
					else
						vbr_result = "permerror";

					break;

				  case VBR_STAT_OK:
					add_vbr_header = TRUE;
					break;

				  default:
					assert(0);
				}

				if (add_vbr_header)
				{
					snprintf((char *) header,
					         sizeof header,
					         "%s%s%s%s vbr=%s header.md=%s",
					         cc->cctx_noleadspc ? " " : "",
					         authservid,
					         conf->conf_authservidwithjobid ? "/"
					                                        : "",
					         conf->conf_authservidwithjobid ? (char *) dfc->mctx_jobid
					                                        : "",
					         vbr_result,
					         vbr_domain);

					if (vbr_certifier != NULL)
					{
						strlcat(header,
						        " header.mv=",
						        sizeof header);
						strlcat(header,
						        vbr_certifier,
						        sizeof header);
					}
		
					if (dkimf_insheader(ctx, 1,
					                    AUTHRESULTSHDR,
					                    (char *) header) == MI_FAILURE)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_ERR,
							       "%s: %s header add failed",
							       dfc->mctx_jobid,
							       AUTHRESULTSHDR);
						}
					}

					break;
				}
			}
		}
#endif /* _FFR_VBR */

		if (conf->conf_redirect != NULL &&
		    dfc->mctx_status == DKIMF_STATUS_BAD)
		{
			struct addrlist *a;

			/* convert all recipients to headers */
			for (a = dfc->mctx_rcptlist;
			     a != NULL;
			     a = a->a_next)
			{
				if (dkimf_delrcpt(ctx,
				                  a->a_addr) != MI_SUCCESS)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: smfi_delrcpt() failed",
						       dfc->mctx_jobid);
					}

					return SMFIS_TEMPFAIL;
				}

				snprintf(header, sizeof header,
				         "rfc822;%s", a->a_addr);
				if (dkimf_addheader(ctx, ORCPTHEADER,
				                    header) != MI_SUCCESS)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s: smfi_addheader() failed",
						       dfc->mctx_jobid);
					}

					return SMFIS_TEMPFAIL;
				}
			}

			/* add our recipient */
			if (dkimf_addrcpt(ctx,
			                  conf->conf_redirect) != MI_SUCCESS)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: smfi_addrcpt() failed",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}
		}
	}

#ifdef USE_LUA
	if (conf->conf_finalscript != NULL)
	{
		_Bool dofree = TRUE;
		struct dkimf_lua_script_result lres;

		memset(&lres, '\0', sizeof lres);

		dfc->mctx_mresult = SMFIS_CONTINUE;

		status = dkimf_lua_final_hook(ctx, conf->conf_finalfunc,
		                              conf->conf_finalfuncsz,
		                              "final script", &lres,
		                              NULL, NULL);

		if (status != 0)
		{
			if (conf->conf_dolog)
			{
				if (lres.lrs_error == NULL)
				{
					dofree = FALSE;

					switch (status)
					{
					  case 2:
						lres.lrs_error = "processing error";
						break;

					  case 1:
						lres.lrs_error = "syntax error";
						break;

					  case -1:
						lres.lrs_error = "memory allocation error";
						break;

					  default:
						lres.lrs_error = "unknown error";
						break;
					}
				}

				syslog(LOG_ERR,
				       "%s: dkimf_lua_final_hook() failed: %s",
				       dfc->mctx_jobid, lres.lrs_error);
			}

			if (dofree)
				free(lres.lrs_error);

			return SMFIS_TEMPFAIL;
		}

		if (dfc->mctx_mresult != SMFIS_CONTINUE &&
		    dfc->mctx_mresult != SMFIS_ACCEPT)
			return dfc->mctx_mresult;
	}
#endif /* USE_LUA */

	/* complete signing if requested */
#ifdef _FFR_RESIGN
	if (dfc->mctx_srhead != NULL &&
	    (!dfc->mctx_resign || conf->conf_resignall ||
	     dfc->mctx_status == DKIMF_STATUS_GOOD))
#else /* _FFR_RESIGN */
	if (dfc->mctx_srhead != NULL)
#endif /* _FFR_RESIGN */
	{
		size_t len;
		u_char *start;
		struct signreq *sr;

		status = dkimf_msr_eom(dfc->mctx_srhead, &lastdkim);
		if (status != DKIM_STAT_OK)
		{
			dkimf_log_ssl_errors(lastdkim, NULL,
			                     (char *) dfc->mctx_jobid);
			return dkimf_libstatus(ctx, lastdkim, "dkim_eom()",
			                       status);
		}

		if (dfc->mctx_tmpstr == NULL)
		{
			dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);

			if (dfc->mctx_tmpstr == NULL)
			{
				syslog(LOG_WARNING,
				       "%s: dkimf_dstring_new() failed",
				       dfc->mctx_jobid);

				return SMFIS_TEMPFAIL;
			}
		}
		else
		{
			dkimf_dstring_blank(dfc->mctx_tmpstr);
		}

		for (sr = dfc->mctx_srhead;
		     sr != NULL;
		     sr = sr->srq_next)
		{
			dkimf_dstring_blank(dfc->mctx_tmpstr);
			if (cc->cctx_noleadspc)
				dkimf_dstring_cat1(dfc->mctx_tmpstr, ' ');

			lastdkim = sr->srq_dkim;
			status = dkim_getsighdr_d(sr->srq_dkim,
		                                  strlen(DKIM_SIGNHEADER) + 2,
		                                  &start, &len);
			if (status != DKIM_STAT_OK)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: dkim_getsighdr() failed",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}

			/* XXX -- check "len" for oversize? */

			dkimf_stripcr((char *) start);
			dkimf_dstring_cat(dfc->mctx_tmpstr, start);

			if (dkimf_insheader(ctx, 1, DKIM_SIGNHEADER,
			                    (char *) dkimf_dstring_get(dfc->mctx_tmpstr)) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: %s header add failed",
					       dfc->mctx_jobid,
					       DKIM_SIGNHEADER);
				}
			}
			else if (conf->conf_dolog_success)
			{
				char *d;
				char *s;

				if (sr->srq_domain != NULL)
					d = sr->srq_domain;
				else
					d = dfc->mctx_domain;

				if (sr->srq_selector != NULL)
					s = sr->srq_selector;
				else
					s = conf->conf_selector;

				syslog(LOG_INFO,
				       "%s: %s field added (s=%s, d=%s)",
				       dfc->mctx_jobid, DKIM_SIGNHEADER, s, d);
			}
		}

#ifdef _FFR_VBR
		/* add VBR-Info header if generated */
		if (dfc->mctx_vbrinfo != NULL)
		{
			if (dkimf_insheader(ctx, 1, VBR_INFOHEADER,
			                    dfc->mctx_vbrinfo) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: %s header add failed",
					       dfc->mctx_jobid,
					       VBR_INFOHEADER);
				}
			}
		}

		if (conf->conf_vbr_purge && dfc->mctx_vbrpurge)
		{
			if (dkimf_chgheader(ctx, VBRTYPEHEADER,
			                    0, NULL) != MI_SUCCESS ||
			     conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: %s header remove failed",
				       dfc->mctx_jobid, VBRTYPEHEADER);
			}

			if (dkimf_chgheader(ctx, VBRCERTHEADER,
			                    0, NULL) != MI_SUCCESS ||
			     conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: %s header remove failed",
				       dfc->mctx_jobid, VBRCERTHEADER);
			}
		}
#endif /* _FFR_VBR */
	}

	/*
	**  Identify the filter, if requested.
	*/

	if (conf->conf_addswhdr)
	{
		char xfhdr[DKIM_MAXHEADER + 1];

		memset(xfhdr, '\0', sizeof xfhdr);

		snprintf(xfhdr, DKIM_MAXHEADER, "%s%s v%s %s %s",
		         cc->cctx_noleadspc ? " " : "",
		         DKIMF_PRODUCT, VERSION, hostname,
		         dfc->mctx_jobid != NULL ? dfc->mctx_jobid
		                                 : (u_char *) JOBIDUNKNOWN);

		if (dkimf_insheader(ctx, 1, SWHEADERNAME, xfhdr) != MI_SUCCESS)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: %s header add failed",
				       dfc->mctx_jobid, SWHEADERNAME);
			}

			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	if (lastdkim != NULL)
		dkimf_log_ssl_errors(lastdkim, sig, (char *) dfc->mctx_jobid);

	/*
	**  If we got this far, we're ready to complete.
	*/

	ret = SMFIS_ACCEPT;

	/* translate the stored status */
	switch (dfc->mctx_status)
	{
	  case DKIMF_STATUS_GOOD:
		break;

	  case DKIMF_STATUS_BAD:
		ret = dkimf_libstatus(ctx, lastdkim, "mlfi_eom()",
		                      DKIM_STAT_BADSIG);
		if ((ret == SMFIS_REJECT || ret == SMFIS_TEMPFAIL ||
		     ret == SMFIS_DISCARD) &&
		    testkey)
			ret = SMFIS_ACCEPT;
		break;

	  case DKIMF_STATUS_NOKEY:
		ret = dkimf_libstatus(ctx, lastdkim, "mlfi_eom()",
		                      DKIM_STAT_NOKEY);
		break;

	  case DKIMF_STATUS_REVOKED:
		ret = dkimf_libstatus(ctx, lastdkim, "mlfi_eom()",
		                      DKIM_STAT_REVOKED);
		break;

	  case DKIMF_STATUS_NOSIGNATURE:
		if (!dfc->mctx_addheader)
		{
			ret = dkimf_libstatus(ctx, lastdkim, "mlfi_eom()",
			                      DKIM_STAT_NOSIG);
		}
		break;

	  case DKIMF_STATUS_BADFORMAT:
		ret = SMFIS_ACCEPT;
		break;

	  case DKIMF_STATUS_UNKNOWN:
		break;

	  default:
		if (status != DKIM_STAT_OK)
			ret = dkimf_libstatus(ctx, NULL, "mlfi_eom()", status);
		break;
	}

	return ret;
}

/*
**  MLFI_ABORT -- handler called if an earlier filter in the filter process
**                rejects the message
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_abort(SMFICTX *ctx)
{
	dkimf_cleanup(ctx);
	return SMFIS_CONTINUE;
}

/*
**  MLFI_CLOSE -- handler called on connection shutdown
**
**  Parameters:
**  	ctx -- milter context
**
**  Return value:
**  	An SMFIS_* constant.
*/

sfsistat
mlfi_close(SMFICTX *ctx)
{
	connctx cc;

	dkimf_cleanup(ctx);

	cc = (connctx) dkimf_getpriv(ctx);
	if (cc != NULL)
	{
		pthread_mutex_lock(&conf_lock);

		cc->cctx_config->conf_refcnt--;

		if (cc->cctx_config->conf_refcnt == 0 &&
		    cc->cctx_config != curconf)
			dkimf_config_free(cc->cctx_config);

		pthread_mutex_unlock(&conf_lock);

		free(cc);
		dkimf_setpriv(ctx, NULL);
	}

#ifdef QUERY_CACHE
	if (querycache)
	{
		time_t now;

		(void) time(&now);
		if (cache_lastlog + CACHESTATSINT < now)
		{
			u_int c_hits;
			u_int c_queries;
			u_int c_expired;
			u_int c_pct;
			u_int c_keys;

			dkim_getcachestats(cc->cctx_config->conf_libopendkim,
			                   &c_queries, &c_hits, &c_expired,
			                   &c_keys, FALSE);

			cache_lastlog = now;

			if (c_queries == 0)
				c_pct = 0;
			else
				c_pct = (c_hits * 100) / c_queries;

			syslog(LOG_INFO,
			       "cache: %u quer%s, %u hit%s (%d%%), %u expired, %u key%s",
			       c_queries, c_queries == 1 ? "y" : "ies",
			       c_hits, c_hits == 1 ? "" : "s",
			       c_pct, c_expired,
			       c_keys, c_keys == 1 ? "" : "s");
		}
	}
#endif /* QUERY_CACHE */

	return SMFIS_CONTINUE;
}

/*
**  smfilter -- the milter module description
*/

struct smfiDesc smfilter =
{
	DKIMF_PRODUCT,	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	0,		/* flags; updated in main() */
	mlfi_connect,	/* connection info filter */
#if SMFI_VERSION == 2
	mlfi_helo,	/* SMTP HELO command filter */
#else /* SMFI_VERSION == 2 */
	NULL,		/* SMTP HELO command filter */
#endif /* SMFI_VERSION == 2 */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* shutdown */
#if SMFI_VERSION > 2
	NULL,		/* unrecognised command */
#endif
#if SMFI_VERSION > 3
	NULL,		/* DATA */
#endif
#if SMFI_VERSION >= 0x01000000
	mlfi_negotiate	/* negotiation callback */
#endif
};

/*
**  USAGE -- print a usage message and return the appropriate exit status
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE.
*/

static int
usage(void)
{
	fprintf(stderr, "%s: usage: %s -p socketfile [options]\n"
	                "\t-A          \tauto-restart\n"
	                "\t-b modes    \tselect operating modes\n"
	                "\t-c canon    \tcanonicalization to use when signing\n"
	                "\t-d domlist  \tdomains to sign\n"
	                "\t-D          \talso sign subdomains\n"
	                "\t-e name     \textract configuration value and exit\n"
	                "\t-f          \tdon't fork-and-exit\n"
	                "\t-F time     \tfixed timestamp to use when signing (test mode only)\n"
	                "\t-k keyfile  \tlocation of secret key file\n"
	                "\t-l          \tlog activity to system log\n"
	                "\t-L limit    \tsignature limit requirements\n"
	                "\t-n          \tcheck configuration and exit\n"
			"\t-o hdrlist  \tlist of headers to omit from signing\n"
			"\t-P pidfile  \tfile into which to write process ID\n"
	                "\t-q          \tquarantine messages that fail to verify\n"
		        "\t-Q          \tquery test mode\n"
	                "\t-r          \trequire basic RFC5322 header compliance\n"
	                "\t-s selector \tselector to use when signing\n"
	                "\t-S signalg  \tsignature algorithm to use when signing\n"
			"\t-t testfile \tevaluate RFC5322 message in \"testfile\"\n"
			"\t-T timeout  \tDNS timeout (seconds)\n"
	                "\t-u userid   \tchange to specified userid\n"
	                "\t-v          \tincrease verbosity during testing\n"
	                "\t-V          \tprint version number and terminate\n"
	                "\t-W          \t\"why?!\" mode (log sign/verify decision logic)\n"
	                "\t-x conffile \tread configuration from conffile\n",
	        progname, progname);
	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Process command line arguments and call the milter mainline.
*/

int
main(int argc, char **argv)
{
	_Bool autorestart = FALSE;
	_Bool gotp = FALSE;
	_Bool dofork = TRUE;
	_Bool stricttest = FALSE;
	_Bool configonly = FALSE;
	_Bool querytest = FALSE;
	int c;
	int status;
	int n;
	int verbose = 0;
	int maxrestarts = 0;
	int maxrestartrate_n = 0;
	int filemask = -1;
	int mdebug = 0;
#ifdef HAVE_SMFI_VERSION
	u_int mvmajor;
	u_int mvminor;
	u_int mvrelease;
#endif /* HAVE_SMFI_VERSION */
	time_t now;
	gid_t gid = (gid_t) -1;
	sigset_t sigset;
	uint64_t fixedtime = (uint64_t) -1;
	time_t maxrestartrate_t = 0;
	pthread_t rt;
	unsigned long tmpl;
	const char *args = CMDLINEOPTS;
	FILE *f;
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	char *become = NULL;
	char *chrootdir = NULL;
	char *extract = NULL;
	char *p;
	char *pidfile = NULL;
#ifdef POPAUTH
	char *popdbfile = NULL;
#endif /* POPAUTH */
	char *testfile = NULL;
	char *testpubkeys = NULL;
	struct config *cfg = NULL;
	char *end;
	char argstr[MAXARGV];
	char err[BUFRSZ + 1];

	/* initialize */
	reload = FALSE;
	testmode = FALSE;
#ifdef QUERY_CACHE
	querycache = FALSE;
#endif /* QUERY_CACHE */
	sock = NULL;
#ifdef POPAUTH
	popdb = NULL;
#endif /* POPAUTH */
	no_i_whine = TRUE;
	conffile = NULL;

	memset(myhostname, '\0', sizeof myhostname);
	(void) gethostname(myhostname, sizeof myhostname);

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	(void) time(&now);
	srandom(now);

	curconf = dkimf_config_new();
	if (curconf == NULL)
	{
		fprintf(stderr, "%s: malloc(): %s\n", progname,
		        strerror(errno));

		return EX_OSERR;
	}

	/* process command line options */
	while ((c = getopt(argc, argv, args)) != -1)
	{
		switch (c)
		{
		  case 'A':
			autorestart = TRUE;
			break;

		  case 'b':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_modestr = optarg;
			break;

		  case 'c':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_canonstr = optarg;
			break;

		  case 'd':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_domlist = strdup(optarg);
			if (curconf->conf_domlist == NULL)
			{
				fprintf(stderr, "%s: strdup(): %s\n", progname,
				        strerror(errno));
				return EX_SOFTWARE;
			}
			break;

		  case 'D':
			curconf->conf_subdomains = TRUE;
			break;

		  case 'e':
			extract = optarg;
			break;

		  case 'f':
			dofork = FALSE;
			break;

		  case 'F':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			errno = 0;
			if (optarg[0] == '-')
			{
				errno = ERANGE;
				fixedtime = ULONG_MAX;
			}
			else
			{
				fixedtime = strtoul(optarg, &p, 10);
			}

			if (fixedtime == (uint64_t) ULONG_MAX ||
			    errno != 0 ||
			    *p != '\0')
			{
				fprintf(stderr, "%s: invalid time value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'k':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_keyfile = optarg;
			break;

		  case 'l':
			curconf->conf_dolog = TRUE;
			break;

		  case 'L':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_siglimit = optarg;
			break;

		  case 'n':
			configonly = TRUE;
			break;

		  case 'o':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_omitlist = optarg;
			break;

		  case 'p':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			sock = optarg;
			(void) smfi_setconn(optarg);
			gotp = TRUE;
			break;

		  case 'P':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			pidfile = optarg;
			break;

		  case 'Q':
			querytest = TRUE;
			testmode = TRUE;
			break;

		  case 'r':
			curconf->conf_reqhdrs = TRUE;
			break;

		  case 's':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_selector = (u_char *) optarg;
			break;

		  case 'S':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_signalgstr = optarg;
			break;

		  case 't':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			testmode = TRUE;
			testfile = optarg;
			break;

		  case 'T':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			errno = 0;
			if (optarg[0] == '-')
			{
				errno = ERANGE;
				tmpl = ULONG_MAX;
			}
			else
			{
				tmpl = strtoul(optarg, &p, 10);
			}

			if (tmpl == ULONG_MAX || errno != 0 || *p != '\0')
			{
				fprintf(stderr, "%s: invalid value for -%c\n",
				        progname, c);
				return EX_USAGE;
			}

			curconf->conf_dnstimeout = (unsigned int) tmpl;

			break;

		  case 'u':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			become = optarg;
			break;

		  case 'v':
			verbose++;
			break;

		  case 'V':
			if (!dkimf_config_setlib(curconf, &p))
			{
				fprintf(stderr,
				        "%s: can't configure DKIM library: %s\n",
				        progname, p);

				return EX_SOFTWARE;
			}

			printf("%s: %s v%s\n", progname, DKIMF_PRODUCT,
			       VERSION);
#ifdef USE_GNUTLS
			printf("\tCompiled with GnuTLS %s\n", GNUTLS_VERSION);
#else /* USE_GNUTLS */
			printf("\tCompiled with %s\n",
			       SSLeay_version(SSLEAY_VERSION));
#endif /* USE_GNUTLS */
			printf("\tSMFI_VERSION 0x%x\n", SMFI_VERSION);
#ifdef HAVE_SMFI_VERSION
			(void) smfi_version(&mvmajor, &mvminor, &mvrelease);
			printf("\tlibmilter version %d.%d.%d\n",
			       mvmajor, mvminor, mvrelease);
#endif /* HAVE_SMFI_VERSION */
			printf("\tSupported signing algorithms:\n");
			for (c = 0; dkimf_sign[c].str != NULL; c++)
			{
				if (dkimf_sign[c].code != DKIM_SIGN_RSASHA256 ||
	    			    dkim_libfeature(curconf->conf_libopendkim,
				                    DKIM_FEATURE_SHA256))
					printf("\t\t%s\n", dkimf_sign[c].str);
			}
			printf("\tSupported canonicalization algorithms:\n");
			for (c = 0; dkimf_canon[c].str != NULL; c++)
				printf("\t\t%s\n", dkimf_canon[c].str);
			dkimf_optlist(stdout);
			return EX_OK;

		  case 'W':
			curconf->conf_logwhy = TRUE;
			break;

		  case 'x':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			else
				conffile = optarg;
			break;

		  case 'X':
			allowdeprecated = TRUE;
			break;

		  default:
			return usage();
		}
	}

	if (optind != argc)
		return usage();

#ifdef USE_GNUTLS
	if (dkim_ssl_version() != GNUTLS_VERSION_NUMBER * 256)
#else /* USE_GNUTLS */
	if (dkim_ssl_version() != OPENSSL_VERSION_NUMBER)
#endif /* USE_GNUTLS */
	{
		fprintf(stderr,
		        "%s: incompatible SSL versions (library = 0x%09lx, filter = %09lx)\n",
		        progname, dkim_ssl_version(),
#ifdef USE_GNUTLS
		        (unsigned long) GNUTLS_VERSION_NUMBER * 256);
#else /* USE_GNUTLS */
		        (unsigned long) OPENSSL_VERSION_NUMBER);
#endif /* USE_GNUTLS */

		return EX_SOFTWARE;
	}

	/* if there's a default config file readable, use it */
	if (conffile == NULL && access(DEFCONFFILE, R_OK) == 0)
	{
		conffile = DEFCONFFILE;
		if (verbose > 1)
		{
			fprintf(stderr, "%s: using default configfile %s\n",
				progname, DEFCONFFILE);
		}
	}

	if (conffile != NULL)
	{
		u_int line = 0;
		char *missing;
		char *deprecated = NULL;
		char path[MAXPATHLEN + 1];

		cfg = config_load(conffile, dkimf_config,
		                  &line, path, sizeof path, &deprecated);

		if (cfg == NULL)
		{
			fprintf(stderr,
			        "%s: %s: configuration error at line %u: %s\n",
			        progname, path, line,
			        config_error());
			dkimf_config_free(curconf);
			return EX_CONFIG;
		}

#ifdef DEBUG
		(void) config_dump(cfg, stdout, NULL);
#endif /* DEBUG */

		missing = config_check(cfg, dkimf_config);
		if (missing != NULL)
		{
			fprintf(stderr,
			        "%s: %s: required parameter \"%s\" missing\n",
			        progname, conffile, missing);
			config_free(cfg);
			dkimf_config_free(curconf);
			return EX_CONFIG;
		}

		if (deprecated != NULL)
		{
			char *action = "aborting";
			if (allowdeprecated)
				action = "continuing";

			fprintf(stderr,
			        "%s: %s: settings found for deprecated value(s): %s; %s\n",
			        progname, conffile, deprecated, action);

			if (!allowdeprecated)
			{
				config_free(cfg);
				dkimf_config_free(curconf);
				return EX_CONFIG;
			}
		}
	}

	if (dkimf_config_load(cfg, curconf, err, sizeof err, become) != 0)
	{
		if (conffile == NULL)
			conffile = "(stdin)";
		fprintf(stderr, "%s: %s: %s\n", progname, conffile, err);
		config_free(cfg);
		dkimf_config_free(curconf);
		return EX_CONFIG;
	}

	if (configonly)
	{
		config_free(cfg);
		dkimf_config_free(curconf);
		return EX_OK;
	}

	if (extract)
	{
		int ret = EX_OK;

		if (cfg != NULL)
		{
			if (!config_validname(dkimf_config, extract))
				ret = EX_DATAERR;
			else if (config_dump(cfg, stdout, extract) == 0)
				ret = EX_CONFIG;
			config_free(cfg);
			dkimf_config_free(curconf);
		}
		return ret;
	}

	dolog = curconf->conf_dolog;
	curconf->conf_data = cfg;

#ifdef _FFR_REPUTATION
	/* power up the reputation code */
	repute_init();

	if (curconf->conf_reptimeout != 0L)
		repute_set_timeout(curconf->conf_reptimeout);
#endif /* _FFR_REPUTATION */

	if (querytest)
	{
		_Bool exists = FALSE;
		DKIMF_DB dbtest;
		DKIMF_DBDATA dbdp;
		char *p;
		char dbname[BUFRSZ + 1];
		char query[BUFRSZ + 1];
		char **result;

		if (isatty(0))
		{
			fprintf(stdout, "%s: enter data set description\n",
			        progname);
			fprintf(stdout, "\tcsl:entry1[,entry2[,...]]\n"
			                "\tfile:path\n"
			                "\trefile:path\n"
			                "\tdb:path\n"
#ifdef USE_ODBX
			                "\tdsn:<backend>://[user[:pwd]@][port+]host/dbase[/key=val[?...]]\n"
#endif /* USE_ODBX */
#ifdef USE_LDAP
			                "\tldapscheme://host[:port][/dn[?attrs[?scope[?filter[?exts]]]]]\n"
#endif /* USE_LDAP */
#ifdef USE_LUA
			                "\tlua:path\n"
#endif /* USE_LUA */
#ifdef USE_LIBMEMCACHED
			                "\tmemcache:host[:port][,...]/prefix\n"
#endif /* USE_LIBMEMCACHED */
#ifdef _FFR_REPUTATION
			                "\trepute:server[:reporter]\n"
#endif /* _FFR_REPUTATION */
#ifdef _FFR_SOCKETDB
			                "\tsocket:{ port@host | path}\n"
#endif /* _FFR_SOCKETDB */
#ifdef USE_MDB
			                "\tmdb:path\n"
#endif /* USE_MDB */
#ifdef USE_ERLANG
					"\terlang:node@host[,...]:cookie:module:function\n"
#endif /* USE_ERLANG */
			                "> ");
		}

		memset(dbname, '\0', sizeof dbname);
		if (fgets(dbname, BUFRSZ, stdin) != dbname)
		{
			fprintf(stderr, "%s: fgets(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}

		p = strchr(dbname, '\n');
		if (p != NULL)
			*p = '\0';

		for (p = dbname; isspace(*p); p++)
			continue;
		if (p != dbname)
			memmove(dbname, p, strlen(p) + 1);

		p = NULL;
		status = dkimf_db_open(&dbtest, dbname,
		                       (DKIMF_DB_FLAG_READONLY |
		                        DKIMF_DB_FLAG_ASCIIONLY),
		                       NULL, &p);
		if (status != 0)
		{
			fprintf(stderr, "%s: %s: dkimf_db_open(): %s\n",
			        progname, dbname, p);
			return EX_SOFTWARE;
		}

		for (;;)
		{
			if (isatty(0))
			{
				fprintf(stdout,
				        "%s: enter 'query/n' where 'n' is number of fields to request\n> ",
				        progname);
			}

			memset(query, '\0', sizeof query);
			if (fgets(query, BUFRSZ, stdin) != query)
				break;

			p = strchr(query, '\n');
			if (p != NULL)
				*p = '\0';

			if (dkimf_isblank(query))
				continue;

			p = strchr(query, '/');
			if (p == NULL)
			{
				(void) dkimf_db_close(dbtest);
				fprintf(stderr, "%s: invalid query '%s'\n",
				        progname, query);
				return EX_USAGE;
			}

			n = atoi(p + 1);
			if (n < 0)
			{
				(void) dkimf_db_close(dbtest);
				fprintf(stderr, "%s: invalid query '%s'\n",
				        progname, query);
				return EX_USAGE;
			}
	
			result = (char **) malloc(sizeof(char *) * n);
			if (result == NULL)
			{
				fprintf(stderr, "%s: malloc(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}

			for (c = 0; c < n; c++)
			{
				result[c] = (char *) malloc(BUFRSZ + 1);
				if (result[c] == NULL)
				{
					fprintf(stderr, "%s: malloc(): %s\n",
					        progname, strerror(errno));
					free(result);
					return EX_OSERR;
				}
				memset(result[c], '\0', BUFRSZ + 1);
			}

			dbdp = (DKIMF_DBDATA) malloc(sizeof(struct dkimf_db_data) * n);
			if (dbdp == NULL)
			{
				fprintf(stderr, "%s: malloc(): %s\n", progname,
				        strerror(errno));
				free(result);
				return EX_OSERR;
			}

			for (c = 0; c < n; c++)
			{
				dbdp[c].dbdata_buffer = result[c];
				dbdp[c].dbdata_buflen = BUFRSZ;
				dbdp[c].dbdata_flags = 0;
			}

			*p = '\0';

			status = dkimf_db_get(dbtest, query, strlen(query),
			                      dbdp, n, &exists);

			if (status != 0)
			{
				char errbuf[BUFRSZ + 1];

				memset(errbuf, '\0', sizeof errbuf);

				dkimf_db_strerror(dbtest, errbuf,
				                  sizeof errbuf);

				fprintf(stderr,
				        "%s: dkimf_db_get() returned %d: \"%s\"\n",
				        progname, status, errbuf);
			}
			else if (!exists)
			{
				fprintf(stdout,
				        "%s: dkimf_db_get(): record not found\n",
				        progname);
			}
			else
			{
				for (c = 0; c < n; c++)
				{
					if (dbdp[c].dbdata_buflen == 0)
						fprintf(stdout, "<empty>\n");
					else if (dbdp[c].dbdata_buflen == (size_t) -1)
						fprintf(stdout, "<absent>\n");
					else
						fprintf(stdout, "'%s'\n", result[c]);
				}
			}

			for (c = 0; c < n; c++)
				free(result[c]);
			free(result);
			free(dbdp);
		}

		fprintf(stdout, "\n");

		dkimf_db_close(dbtest);

		return 0;
	}

	if (testmode && curconf->conf_modestr == NULL)
		curconf->conf_mode = DKIMF_MODE_VERIFIER;

	/*
	**  Use values found in the configuration file, if any.  Note that
	**  these are operational parameters for the filter (e.g which socket
	**  to use which userid to become, etc.) and aren't reloaded upon a
	**  reload signal.  Reloadable values are handled via the
	**  dkimf_config_load() function, which has already been called.
	*/

	if (cfg != NULL)
	{
		if (!autorestart)
		{
			(void) config_get(cfg, "AutoRestart", &autorestart,
			                  sizeof autorestart);
		}

		if (autorestart)
		{
			char *rate = NULL;

			(void) config_get(cfg, "AutoRestartCount",
			                  &maxrestarts, sizeof maxrestarts);

			(void) config_get(cfg, "AutoRestartRate", &rate,
			                  sizeof rate);

			if (rate != NULL)
			{
				time_t t;
				char *q;

				p = strchr(rate, '/');
				if (p == NULL)
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				*p = '\0';
				n = strtol(rate, &q, 10);
				if (n < 0 || *q != '\0')
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				t = (time_t) strtoul(p + 1, &q, 10);
				switch (*q)
				{
				  case 'd':
				  case 'D':
					t *= 86400;
					break;

				  case 'h':
				  case 'H':
					t *= 3600;
					break;

				  case 'm':
				  case 'M':
					t *= 60;
					break;

				  case '\0':
				  case 's':
				  case 'S':
					break;

				  default:
					t = 0;
					break;
				}

				if (*q != '\0' && *(q + 1) != '\0')
					t = 0;

				if (t == 0)
				{
					fprintf(stderr,
					        "%s: AutoRestartRate invalid\n",
					        progname);
					config_free(cfg);
					return EX_CONFIG;
				}

				maxrestartrate_n = n;
				maxrestartrate_t = t;
			}
		}

		if (dofork)
		{
			(void) config_get(cfg, "Background", &dofork,
			                  sizeof dofork);
		}

		(void) config_get(cfg, "TestPublicKeys",
		                  &testpubkeys, sizeof testpubkeys);

		(void) config_get(cfg, "StrictTestMode", &stricttest,
		                  sizeof stricttest);

		(void) config_get(cfg, "MilterDebug", &mdebug, sizeof mdebug);

		if (!gotp)
		{
			(void) config_get(cfg, "Socket", &sock, sizeof sock);
			if (sock != NULL)
			{
				gotp = TRUE;
				(void) smfi_setconn(sock);
			}
		}

		if (pidfile == NULL)
		{
			(void) config_get(cfg, "PidFile", &pidfile,
			                  sizeof pidfile);
		}

#ifdef QUERY_CACHE
		(void) config_get(cfg, "QueryCache", &querycache,
		                  sizeof querycache);
#endif /* QUERY_CACHE */

		(void) config_get(cfg, "UMask", &filemask, sizeof filemask);

		if (become == NULL)
		{
			(void) config_get(cfg, "Userid", &become,
			                  sizeof become);
		}

#ifdef POPAUTH
		if (popdbfile == NULL)
		{
			(void) config_get(cfg, "POPDBFile", &popdbfile,
			                  sizeof popdbfile);
		}
#endif /* POPAUTH */

		(void) config_get(cfg, "ChangeRootDirectory", &chrootdir,
		                  sizeof chrootdir);
	}

#ifndef SMFIF_QUARANTINE
	if (quarantine)
	{
		fprintf(stderr, "%s: quarantine service not available\n",
		        progname);
		return EX_SOFTWARE;
	}
#endif /* ! SMFIF_QUARANTINE */

	if (!gotp && !testmode)
	{
		fprintf(stderr, "%s: milter socket must be specified\n",
		        progname);
		if (argc == 1)
			fprintf(stderr, "\t(use \"-?\" for help)\n");
		return EX_CONFIG;
	}

	/* suppress a bunch of things if we're in test mode */
	if (testmode)
	{
		curconf->conf_dolog = FALSE;
		curconf->conf_sendreports = FALSE;
		autorestart = FALSE;
		dofork = FALSE;
		become = NULL;
		pidfile = NULL;
		chrootdir = NULL;
	}

	dkimf_setmaxfd();

	/* prepare to change user if appropriate */
	if (become != NULL)
	{
		char *colon;

		/* see if there was a group specified; if so, validate */
		colon = strchr(become, ':');
		if (colon != NULL)
		{
			*colon = '\0';

			gr = getgrnam(colon + 1);
			if (gr == NULL)
			{
				char *q;

				gid = (gid_t) strtol(colon + 1, &q, 10);
				if (*q == '\0')
					gr = getgrgid(gid);

				if (gr == NULL)
				{
					if (curconf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "no such group or gid '%s'",
						       colon + 1);
					}

					fprintf(stderr,
					        "%s: no such group '%s'\n",
					        progname, colon + 1);

					return EX_DATAERR;
				}
			}
		}

		/* validate the user */
		pw = getpwnam(become);
		if (pw == NULL)
		{
			char *q;
			uid_t uid;

			uid = (uid_t) strtoul(become, &q, 10);
			if (*q == '\0')
				pw = getpwuid(uid);

			if (pw == NULL)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "no such user or uid '%s'",
					       become);
				}

				fprintf(stderr, "%s: no such user '%s'\n",
				        progname, become);

				return EX_DATAERR;
			}
		}

		if (gr == NULL)
			gid = pw->pw_gid;
		else
			gid = gr->gr_gid;

		(void) endpwent();

#ifdef _FFR_REPUTATION
		/* chown things that need chowning */
		if (curconf->conf_rep != NULL)
		{
			(void) dkimf_rep_chown_cache(curconf->conf_rep,
			                             pw->pw_uid);
		}
#endif /* _FFR_REPUTATION */
	}

	/* change root if requested */
	if (chrootdir != NULL)
	{
		/* warn if doing so as root without then giving up root */
		if (become == NULL && getuid() == 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "using ChangeRootDirectory without Userid not advised");
			}

			fprintf(stderr,
			        "%s: use of ChangeRootDirectory without Userid not advised\n",
			        progname);
		}

		/* change to the new root first */
		if (chdir(chrootdir) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: chdir(): %s",
				       chrootdir, strerror(errno));
			}

			fprintf(stderr, "%s: %s: chdir(): %s\n", progname,
			        chrootdir, strerror(errno));
			return EX_OSERR;
		}

		/* now change the root */
		if (chroot(chrootdir) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "%s: chroot(): %s",
				       chrootdir, strerror(errno));
			}

			fprintf(stderr, "%s: %s: chroot(): %s\n", progname,
			        chrootdir, strerror(errno));
			return EX_OSERR;
		}
	}

	if (curconf->conf_enablecores)
	{
		_Bool enabled = FALSE;

#ifdef __linux__
		if (prctl(PR_SET_DUMPABLE, 1) == -1)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "prctl(): %s",
				       strerror(errno));
			}

			fprintf(stderr, "%s: prctl(): %s\n",
			        progname, strerror(errno));
		}
		else
		{
			enabled = TRUE;
		}
#endif /* __linux__ */

		if (!enabled)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "can't enable coredumps; continuing");
			}

			fprintf(stderr,
			        "%s: can't enable coredumps; continuing\n",
			        progname);
		}
	}

	die = FALSE;

	if (autorestart)
	{
		_Bool quitloop = FALSE;
		int restarts = 0;
		int status;
		pid_t pid;
		pid_t wpid;
		struct sigaction sa;

		if (dofork)
		{
			pid = fork();
			switch (pid)
			{
			  case -1:
				if (curconf->conf_dolog)
				{
					int saveerrno;

					saveerrno = errno;

					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));

					errno = saveerrno;
				}

				fprintf(stderr, "%s: fork(): %s\n",
				        progname, strerror(errno));

				dkimf_zapkey(curconf);
				return EX_OSERR;

			  case 0:
				dkimf_stdio();
				break;

			  default:
				dkimf_zapkey(curconf);
				return EX_OK;
			}
		}

		if (pidfile != NULL)
		{
			f = fopen(pidfile, "w");
			if (f != NULL)
			{
				fprintf(f, "%ld\n", (long) getpid());
				(void) fclose(f);
			}
			else
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "can't write pid to %s: %s",
					       pidfile, strerror(errno));
				}
			}
		}

		sa.sa_handler = dkimf_sighandler;
		/* XXX -- HAHAHAH => sa.sa_sigaction = NULL; */
		sigemptyset(&sa.sa_mask);
		sigaddset(&sa.sa_mask, SIGHUP);
		sigaddset(&sa.sa_mask, SIGINT);
		sigaddset(&sa.sa_mask, SIGTERM);
		sigaddset(&sa.sa_mask, SIGUSR1);
		sa.sa_flags = 0;

		if (sigaction(SIGHUP, &sa, NULL) != 0 ||
		    sigaction(SIGINT, &sa, NULL) != 0 ||
		    sigaction(SIGTERM, &sa, NULL) != 0 ||
		    sigaction(SIGUSR1, &sa, NULL) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "[parent] sigaction(): %s",
				       strerror(errno));
			}
		}

		/* now enact the user change */
		if (become != NULL)
		{
			/* make all the process changes */
			if (getuid() != pw->pw_uid)
			{
				if (initgroups(pw->pw_name, gid) != 0)
				{
					if (curconf->conf_dolog)
						syslog(LOG_ERR, "initgroups(): %s", strerror(errno));
					fprintf(stderr, "%s: initgroups(): %s", progname, strerror(errno));
					return EX_NOPERM;
				}
				else if (setgid(gid) != 0)
				{
					if (curconf->conf_dolog)
						syslog(LOG_ERR, "setgid(): %s", strerror(errno));
					fprintf(stderr, "%s: setgid(): %s", progname, strerror(errno));
					return EX_NOPERM;
				}
				else if (setuid(pw->pw_uid) != 0)
				{
					if (curconf->conf_dolog)
						syslog(LOG_ERR, "setuid(): %s", strerror(errno));
					fprintf(stderr, "%s: setuid(): %s", progname, strerror(errno));
					return EX_NOPERM;
				}
			}
		}

		if (maxrestartrate_n > 0)
			dkimf_restart_check(maxrestartrate_n, 0);

		while (!quitloop)
		{
			status = dkimf_socket_cleanup(sock);
			if (status != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "[parent] socket cleanup failed: %s",
					       strerror(status));
				}
				return EX_UNAVAILABLE;
			}

			pid = fork();
			switch (pid)
			{
			  case -1:
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "fork(): %s",
					       strerror(errno));
				}

				dkimf_zapkey(curconf);
				return EX_OSERR;

			  case 0:
				sa.sa_handler = SIG_DFL;

				if (sigaction(SIGHUP, &sa, NULL) != 0 ||
				    sigaction(SIGINT, &sa, NULL) != 0 ||
				    sigaction(SIGTERM, &sa, NULL) != 0)
				{
					if (curconf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "[child] sigaction(): %s",
						       strerror(errno));
					}
				}

				quitloop = TRUE;
				break;

			  default:
				for (;;)
				{
					wpid = wait(&status);

					if (wpid == -1 && errno == EINTR)
					{
						if (die)
						{
							dkimf_killchild(pid,
							                diesig,
							                curconf->conf_dolog);
							dkimf_zapkey(curconf);

							while (wpid != pid)
								wpid = wait(&status);

							if (pidfile != NULL)
								(void) unlink(pidfile);

							exit(EX_OK);
						}
						else if (reload)
						{
							dkimf_killchild(pid,
							                SIGUSR1,
							                curconf->conf_dolog);

							reload = FALSE;

							continue;
						}
					}

					if (pid != wpid)
						continue;

					if (wpid != -1 && curconf->conf_dolog)
					{
						if (WIFSIGNALED(status))
						{
							syslog(LOG_NOTICE,
							       "terminated with signal %d, restarting",
							       WTERMSIG(status));
						}
						else if (WIFEXITED(status))
						{
							if (WEXITSTATUS(status) == EX_CONFIG ||
							    WEXITSTATUS(status) == EX_SOFTWARE)
							{
								syslog(LOG_NOTICE,
								       "exited with status %d",
								       WEXITSTATUS(status));
								quitloop = TRUE;
							}
							else
							{
								syslog(LOG_NOTICE,
								       "exited with status %d, restarting",
								       WEXITSTATUS(status));
							}
						}
					}

					if (conffile != NULL)
						reload = TRUE;

					break;
				}
				break;
			}

			if (maxrestarts > 0 && restarts >= maxrestarts)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "maximum restart count exceeded");
				}

				return EX_UNAVAILABLE;
			}

			if (maxrestartrate_n > 0 &&
			    maxrestartrate_t > 0 &&
			    !dkimf_restart_check(0, maxrestartrate_t))
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "maximum restart rate exceeded");
				}

				return EX_UNAVAILABLE;
			}

			restarts++;
		}
	}

	if (!autorestart && dofork)
	{
		pid_t pid;

		pid = fork();
		switch (pid)
		{
		  case -1:
			if (curconf->conf_dolog)
			{
				int saveerrno;

				saveerrno = errno;

				syslog(LOG_ERR, "fork(): %s", strerror(errno));

				errno = saveerrno;
			}

			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));

			dkimf_zapkey(curconf);

			return EX_OSERR;

		  case 0:
			dkimf_stdio();
			break;

		  default:
			dkimf_zapkey(curconf);
			return EX_OK;
		}
	}

	/* write out the pid */
	if (!autorestart && pidfile != NULL)
	{
		f = fopen(pidfile, "w");
		if (f != NULL)
		{
			fprintf(f, "%ld\n", (long) getpid());
			(void) fclose(f);
		}
		else
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "can't write pid to %s: %s",
				       pidfile, strerror(errno));
			}
		}
	}

	/*
	**  Block SIGUSR1 for use of our reload thread, and SIGHUP, SIGINT
	**  and SIGTERM for use of libmilter's signal handling thread.
	*/

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_sigprocmask(): %s",
			       strerror(status));
		}

		fprintf(stderr, "%s: pthread_sigprocmask(): %s\n", progname,
		        strerror(status));

		dkimf_zapkey(curconf);

		return EX_OSERR;
	}

	/* now enact the user change */
	if (!autorestart && become != NULL)
	{
		/* make all the process changes */
		if (getuid() != pw->pw_uid)
		{
			if (initgroups(pw->pw_name, gid) != 0)
			{
				if (curconf->conf_dolog)
					syslog(LOG_ERR, "initgroups(): %s", strerror(errno));
				fprintf(stderr, "%s: initgroups(): %s", progname, strerror(errno));
				return EX_NOPERM;
			}
			else if (setgid(gid) != 0)
			{
				if (curconf->conf_dolog)
					syslog(LOG_ERR, "setgid(): %s", strerror(errno));
				fprintf(stderr, "%s: setgid(): %s", progname, strerror(errno));
				return EX_NOPERM;
			}
			else if (setuid(pw->pw_uid) != 0)
			{
				if (curconf->conf_dolog)
					syslog(LOG_ERR, "setuid(): %s", strerror(errno));
				fprintf(stderr, "%s: setuid(): %s", progname, strerror(errno));
				return EX_NOPERM;
			}
		}
	}

	/* initialize DKIM library */
	if (!dkimf_config_setlib(curconf, &p))
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "can't configure DKIM library: %s", p);
			fprintf(stderr, "%s: can't configure DKIM library: %s", progname, p);
		return EX_SOFTWARE;
	}

	if (filemask != -1)
		(void) umask((mode_t) filemask);

	if (mdebug > 0)
		(void) smfi_setdbg(mdebug);

	if (!testmode)
	{
		/* try to clean up the socket */
		status = dkimf_socket_cleanup(sock);
		if (status != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "socket cleanup failed: %s",
				       strerror(status));
			}

			fprintf(stderr, "%s: socket cleanup failed: %s\n",
			        progname, strerror(status));

			dkimf_zapkey(curconf);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

		smfilter.xxfi_flags = SMFIF_ADDHDRS;

		if (curconf->conf_redirect != NULL)
		{
			smfilter.xxfi_flags |= SMFIF_ADDRCPT;
			smfilter.xxfi_flags |= SMFIF_DELRCPT;
		}

#ifdef SMFIF_SETSYMLIST
		smfilter.xxfi_flags |= SMFIF_SETSYMLIST;
#endif /* SMFIF_SETSYMLIST */

		if (curconf->conf_remarall ||
		    !curconf->conf_keepar ||
#ifdef _FFR_IDENTITY_HEADER
		    curconf->conf_rmidentityhdr ||
#endif /* _FFR_IDENTITY_HEADER */
#ifdef _FFR_VBR
		    curconf->conf_vbr_purge ||
#endif /* _FFR_VBR */
		    curconf->conf_remsigs)
			smfilter.xxfi_flags |= SMFIF_CHGHDRS;
#ifdef SMFIF_QUARANTINE
		if (curconf->conf_capture)
			smfilter.xxfi_flags |= SMFIF_QUARANTINE;
#endif /* SMFIF_QUARANTINE */

		/* register with the milter interface */
		if (smfi_register(smfilter) == MI_FAILURE)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "smfi_register() failed");

			fprintf(stderr, "%s: smfi_register() failed\n",
			        progname);

			dkimf_zapkey(curconf);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

#ifdef HAVE_SMFI_OPENSOCKET
		/* try to establish the milter socket */
		if (smfi_opensocket(FALSE) == MI_FAILURE)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "smfi_opensocket() failed");

			fprintf(stderr, "%s: smfi_opensocket() failed\n",
			        progname);

			dkimf_zapkey(curconf);

			return EX_UNAVAILABLE;
		}
#endif /* HAVE_SMFI_OPENSOCKET */
	}

	/* initialize libcrypto mutexes */
	if (!curconf->conf_disablecryptoinit)
	{
		status = dkimf_crypto_init();
		if (status != 0)
		{
			fprintf(stderr,
			        "%s: error initializing crypto library: %s\n",
			        progname, strerror(status));
		}
	}

	if ((curconf->conf_mode & DKIMF_MODE_VERIFIER) != 0 &&
	    !dkim_libfeature(curconf->conf_libopendkim, DKIM_FEATURE_SHA256))
	{
		if (curconf->conf_allowsha1only)
		{
			if (dolog)
			{
				syslog(LOG_WARNING,
				       "WARNING: verifier mode operating without rsa-sha256 support");
			}
		}
		else
		{
			if (dolog)
			{
				syslog(LOG_ERR,
				       "verifier mode operating without rsa-sha256 support; terminating");
			}

			fprintf(stderr,
			        "%s: verify mode requires rsa-sha256 support\n",
			        progname);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_CONFIG;
		}
	}

	/* set up for test mode if selected */
	if (testpubkeys != NULL)
	{
		dkim_query_t qtype = DKIM_QUERY_FILE;

		(void) dkim_options(curconf->conf_libopendkim, DKIM_OP_SETOPT,
		                    DKIM_OPTS_QUERYMETHOD,
		                    &qtype, sizeof qtype);
		(void) dkim_options(curconf->conf_libopendkim, DKIM_OP_SETOPT,
		                    DKIM_OPTS_QUERYINFO,
		                    testpubkeys, strlen(testpubkeys));
	}

	pthread_mutex_init(&conf_lock, NULL);
	pthread_mutex_init(&pwdb_lock, NULL);

	/* perform test mode */
	if (testfile != NULL)
	{
		status = dkimf_testfiles(curconf->conf_libopendkim, testfile,
		                         fixedtime, stricttest, verbose);
		dkim_close(curconf->conf_libopendkim);
		return status;
	}

	memset(argstr, '\0', sizeof argstr);
	end = &argstr[sizeof argstr - 1];
	n = sizeof argstr;
	for (c = 1, p = argstr; c < argc && p < end; c++)
	{
		if (strchr(argv[c], ' ') != NULL)
		{
			status = snprintf(p, n, "%s \"%s\"",
			                  c == 1 ? "args:" : "",
			                  argv[c]);
		}
		else
		{
			status = snprintf(p, n, "%s %s",
			                  c == 1 ? "args:" : "",
			                  argv[c]);
		}

		p += status;
		n -= status;
	}

#ifdef POPAUTH
	if (popdbfile != NULL)
	{
		char *err = NULL;

		status = dkimf_initpopauth();
		if (status != 0)
		{
			fprintf(stderr,
			        "%s: can't initialize popauth mutex: %s\n",
			        progname, strerror(status));
			syslog(LOG_ERR, "can't initialize mutex: %s",
			       popdbfile);
		}

		status = dkimf_db_open(&popdb, popdbfile,
		                       DKIMF_DB_FLAG_READONLY, NULL, &err);
		if (status != 0)
		{
			fprintf(stderr, "%s: can't open database %s: %s\n",
			        progname, popdbfile, err);

			if (dolog)
			{
				syslog(LOG_ERR, "can't open database %s: %s",
				       popdbfile, err);
			}

			dkimf_zapkey(curconf);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}
	}
#endif /* POPAUTH */

#ifdef _FFR_STATS
	dkimf_stats_init();
#endif /* _FFR_STATS */

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO, "%s v%s starting (%s)", DKIMF_PRODUCT,
		       VERSION, argstr);
	}

	/* spawn the SIGUSR1 handler */
	status = pthread_create(&rt, NULL, dkimf_reloader, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_create(): %s",
			       strerror(status));
		}

		if (!autorestart && pidfile != NULL)
			(void) unlink(pidfile);

		return EX_OSERR;
	}

	/* call the milter mainline */
	errno = 0;
	status = smfi_main();

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO,
		       "%s v%s terminating with status %d, errno = %d",
		       DKIMF_PRODUCT, VERSION, status, errno);
	}

#ifdef POPAUTH
	if (popdb != NULL)
		dkimf_db_close(popdb);
#endif /* POPAUTH */

	dkimf_zapkey(curconf);

	/* tell the reloader thread to die */
	die = TRUE;
	(void) raise(SIGUSR1);

	if (!autorestart && pidfile != NULL)
		(void) unlink(pidfile);

	dkimf_crypto_free();

	dkimf_config_free(curconf);

	return status;
}
