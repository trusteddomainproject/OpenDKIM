/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim.c,v 1.18 2009/08/19 00:42:30 cm-msk Exp $
*/

#ifndef lint
static char opendkim_c_id[] = "@(#)$Id: opendkim.c,v 1.18 2009/08/19 00:42:30 cm-msk Exp $";
#endif /* !lint */

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
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <regex.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif /* ! _PATH_DEVNULL */
#ifndef _PATH_SENDMAIL
#  define _PATH_SENDMAIL	"/usr/sbin/sendmail"
#endif /* ! _PATH_SENDMAIL */

/* libmilter includes */
#include "libmilter/mfapi.h"

/* libopendkim includes */
#include <dkim.h>
#ifdef _FFR_VBR
# include <vbr.h>
#endif /* _FFR_VBR */
#include <dkim-strl.h>

#if VERIFY_DOMAINKEYS
/* libdk includes */
# include <dk.h>
#endif /* VERIFY_DOMAINKEYS */

/* opendkim includes */
#include "config.h"
#if USE_DB
# include "opendkim-db.h"
#endif /* USE_DB */
#include "opendkim-config.h"
#include "opendkim-crypto.h"
#include "opendkim.h"
#include "opendkim-ar.h"
#include "opendkim-arf.h"
#include "util.h"
#include "test.h"
#ifdef _FFR_STATS
# include "stats.h"
#endif /* _FFR_STATS */

/*
**  HEADER -- a handle referring to a header
*/

typedef struct Header * Header;
struct Header
{
	char *		hdr_hdr;
	char *		hdr_val;
	struct Header *	hdr_next;
};

/*
**  ADDRLIST -- address list
*/

struct addrlist
{
	char *		a_addr;			/* address */
	struct addrlist * a_next;		/* next record */
};

/*
**  KEYTABLE -- table of keys
*/

struct keytable
{
	char *		key_selector;		/* selector */
	char *		key_domain;		/* domain */
	regex_t		key_re;			/* regex for matching */
	size_t		key_len;		/* key length */
	unsigned char *	key_data;		/* private key data */
	struct keytable * key_next;		/* next record */
};

/*
**  HANDLING -- message handling requests
*/

struct handling
{
	int		hndl_nosig;		/* no signature */
	int		hndl_badsig;		/* bad signature */
	int		hndl_dnserr;		/* DNS error */
	int		hndl_internal;		/* internal error */
	int		hndl_security;		/* security concerns */
};

struct handling defaults =
{
	SMFIS_ACCEPT,
	/* SMFIS_REJECT, */ SMFIS_ACCEPT,
	SMFIS_TEMPFAIL,
	SMFIS_TEMPFAIL,
	SMFIS_TEMPFAIL
};

#ifdef _FFR_MULTIPLE_SIGNATURES
/*
**  SIGNREQ -- signing request (for multiple signature requests)
*/

struct signreq
{
	struct keytable	*	srq_key;
	DKIM *			srq_dkim;
	struct signreq *	srq_next;
};
#endif /* _FFR_MULTIPLE_SIGNATURES */

/*
**  CONFIG -- configuration data
*/

struct dkimf_config
{
	_Bool		conf_addxhdr;		/* add identifying header? */
	_Bool		conf_blen;		/* use "l=" when signing */
#ifdef _FFR_COMMAIZE
	_Bool		conf_commaize;		/* clone MTA's commaize() */
#endif /* _FFR_COMMAIZE */
	_Bool		conf_ztags;		/* use "z=" when signing */
	_Bool		conf_alwaysaddar;	/* always add Auth-Results:? */
	_Bool		conf_sendreports;	/* verify failure reports */
	_Bool		conf_sendadspreports;	/* ADSP failure reports */
	_Bool		conf_adspdiscard;	/* apply ADSP "discardable"? */
	_Bool		conf_adspnxdomain;	/* reject on ADSP NXDOMAIN? */
	_Bool		conf_reqhdrs;		/* required header checks */
	_Bool		conf_authservidwithjobid; /* use jobids in A-R headers */
	_Bool		conf_subdomains;	/* sign subdomains */
	_Bool		conf_remsigs;		/* remove current signatures? */
	_Bool		conf_remarall;		/* remove all matching ARs? */
	_Bool		conf_dolog;		/* syslog interesting stuff? */
	_Bool		conf_dolog_success;	/* syslog successes too? */
	_Bool		conf_milterv2;		/* using milter v2? */
	_Bool		conf_multikey;		/* multi-key operation? */
	_Bool		conf_fixcrlf;		/* fix bare CRs and LFs? */
	_Bool		conf_logwhy;		/* log mode decision logic */
	_Bool		conf_allowsha1only;	/* allow rsa-sha1 verifying */
	_Bool		conf_keeptmpfiles;	/* keep temporary files */
#ifdef _FFR_MULTIPLE_SIGNATURES
	_Bool		conf_multisig;		/* multiple signatures */
#endif /* _FFR_MULTIPLE_SIGNATURES */
	_Bool		conf_enablecores;	/* enable coredumps */
	unsigned int	conf_mode;		/* operating mode */
	unsigned int	conf_refcnt;		/* reference count */
	unsigned int	conf_dnstimeout;	/* DNS timeout */
	unsigned int	conf_maxhdrsz;		/* max header bytes */
#ifdef USE_UNBOUND
	unsigned int	conf_boguskey;		/* bogus key action */
	unsigned int	conf_insecurekey;	/* insecure key action */
	unsigned int	conf_boguspolicy;	/* bogus policy action */
	unsigned int	conf_insecurepolicy;	/* insecure policy action */
#endif /* USE_UNBOUND */
	int		conf_clockdrift;	/* tolerable clock drift */
	int		conf_sigmintype;	/* signature minimum type */
	size_t		conf_sigmin;		/* signature minimum */
	size_t		conf_keylen;		/* size of secret key */
#ifdef _FFR_DKIM_REPUTATION
	long		conf_repfail;		/* reputation "fail" limit */
	long		conf_reppass;		/* reputation "pass" limit */
	long		conf_repreject;		/* reputation "reject" limit */
#endif /* _FFR_DKIM_REPUTATION */
	off_t		conf_signbytes;		/* bytes to sign */
	dkim_canon_t 	conf_hdrcanon;		/* canon. method for headers */
	dkim_canon_t 	conf_bodycanon;		/* canon. method for body */
	unsigned long	conf_sigttl;		/* signautre TTLs */
	dkim_alg_t	conf_signalg;		/* signing algorithm */
	struct config *	conf_data;		/* configuration data */
	char *		conf_authservid;	/* authserv-id */
	char *		conf_actions;		/* action configuration */
	char *		conf_keyfile;		/* key file */
	char *		conf_peerfile;		/* peer file */
	char *		conf_internalfile;	/* internal hosts file */
	char *		conf_externalfile;	/* internal hosts file */
	char *		conf_tmpdir;		/* temp directory */
	char *		conf_thirdpartyfile;	/* third party sigs file */
	char *		conf_omitlist;		/* omit header list */
	char *		conf_domlist;		/* signing domain list */
	char *		conf_mtalist;		/* signing MTA list */
	char *		conf_macrolist;		/* signing MTA list */
	char *		conf_signalgstr;	/* signature algorithm string */
	char *		conf_modestr;		/* mode string */
	char *		conf_canonstr;		/* canonicalization(s) string */
	char *		conf_siglimit;		/* signing limits */
	char *		conf_selector;		/* key selector */
#ifdef _FFR_SELECTOR_HEADER
	char *		conf_selectorhdr;	/* selector header */
#endif /* _FFR_SELECTOR_HEADER */
#ifdef _FFR_ZTAGS
	char *		conf_diagdir;		/* diagnostics directory */
#endif /* _FFR_ZTAGS */
#ifdef _FFR_STATS
	char *		conf_statspath;		/* path for stats DB */
#endif /* _FFR_STATS */
#ifdef _FFR_DKIM_REPUTATION
	char *		conf_reproot;		/* root of reputation queries */
#endif /* _FFR_DKIM_REPUTATION */
	char *		conf_reportaddr;	/* report sender address */
	char *		conf_localadsp_file;	/* local ADSP file */
	struct keytable * conf_keyhead;		/* key list */
	struct keytable * conf_keytail;		/* key list */
#ifdef _FFR_REPLACE_RULES
	struct replace * conf_replist;		/* replacement list */
#endif /* _FFR_REPLACE_RULES */
	dkim_sigkey_t	conf_seckey;		/* secret key data */
#ifdef USE_UNBOUND
	char *		conf_trustanchorpath;	/* unbound trust anchor file */
#endif /* USE_UNBOUND */
#ifdef _FFR_VBR
	char *		conf_vbr_defcert;	/* default VBR type */
	char *		conf_vbr_deftype;	/* default VBR certifiers */
	char **		conf_vbr_trusted;	/* trusted certifiers */
#endif /* _FFR_VBR */
	char **		conf_domains;		/* domains to sign */
	char **		conf_omithdrs;		/* headers to omit */
	char **		conf_signhdrs;		/* headers to sign */
	char **		conf_alwayshdrs;	/* always include headers */
	char **		conf_senderhdrs;	/* sender headers */
	char **		conf_mtas;		/* MTA ports to sign */
	char **		conf_remar;		/* A-R header removal list */
	char **		conf_macros;		/* macros/values to check */
	char **		conf_values;		/* macros/values to check */
	char **		conf_mbs;		/* must-be-signed headers */
	char **		conf_dontsignto;	/* don't-sign-mail-to addrs */
	char **		conf_thirdparty;	/* don't-sign-mail-to addrs */
	char **		conf_localadsp_domain;	/* local ADSP domains */
	char **		conf_localadsp_policy;	/* local ADSP policies */
	regex_t **	conf_dompats;		/* domain patterns */
	regex_t **	conf_nosignpats;	/* do-not-sign patterns */
	Peer		conf_peerlist;		/* queue of "peers" */
	Peer		conf_internal;		/* queue of "internal" hosts */
	Peer		conf_exignore;		/* "external ignore" hosts */
	DKIM_LIB *	conf_libopendkim;	/* DKIM library handle */
	struct handling	conf_handling;		/* message handling */
};

/*
**  MSGCTX -- message context, containing transaction-specific data
*/

typedef struct msgctx * msgctx;
struct msgctx
{
	_Bool		mctx_addheader;		/* Authentication-Results: */
	_Bool		mctx_signing;		/* TRUE iff signing */
	_Bool		mctx_headeronly;	/* in EOM, only add headers */
#if _FFR_BODYLENGTH_DB
	_Bool		mctx_ltag;		/* sign with l= tag? */
#endif /*_FFR_BODYLENGTH_DB */
#if VERIFY_DOMAINKEYS
	_Bool		mctx_dksigned;		/* DK signature present */
#endif /* VERIFY_DOMAINKEYS */
#if _FFR_CAPTURE_UNKNOWN_ERRORS
	_Bool		mctx_capture;		/* capture message? */
#endif /* _FFR_CAPTURE_UNKNOWN_ERRORS */
	_Bool		mctx_susp;		/* suspicious message? */
	_Bool		mctx_policy;		/* policy query completed */
	int		mctx_status;		/* status to report back */
	dkim_canon_t	mctx_hdrcanon;		/* header canonicalization */
	dkim_canon_t	mctx_bodycanon;		/* body canonicalization */
	dkim_alg_t	mctx_signalg;		/* signature algorithm */
#ifdef USE_UNBOUND
	int		mctx_dnssec_key;	/* DNSSEC results for key */
	int		mctx_dnssec_policy;	/* DNSSEC results for policy */
#endif /* USE_UNBOUND */
	int		mctx_queryalg;		/* query algorithm */
	int		mctx_hdrbytes;		/* header space allocated */
	struct dkimf_dstring * mctx_tmpstr;	/* temporary string */
	char *		mctx_jobid;		/* job ID */
	DKIM *		mctx_dkim;		/* DKIM handle */
#if VERIFY_DOMAINKEYS
	DK *		mctx_dk;		/* DK handle */
#endif /* VERIFY_DOMAINKEYS */
#ifdef _FFR_VBR
	VBR *		mctx_vbr;		/* VBR handle */
#endif /* _FFR_VBR */
	struct Header *	mctx_hqhead;		/* header queue head */
	struct Header *	mctx_hqtail;		/* header queue tail */
#ifdef _FFR_MULTIPLE_SIGNATURES
	struct signreq * mctx_srhead;		/* signature request head */
	struct signreq * mctx_srtail;		/* signature request tail */
#endif /* _FFR_MULTIPLE_SIGNATURES */
	struct keytable * mctx_key;		/* key information */
	struct addrlist * mctx_rcptlist;	/* recipient list */
	char		mctx_domain[DKIM_MAXHOSTNAMELEN + 1];
						/* primary domain */
	char		mctx_hlist[MAXHEADERS];	/* header buffer */
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
	_SOCK_ADDR	cctx_ip;		/* IP info */
	struct dkimf_config * cctx_config;	/* configuration in use */
	struct msgctx *	cctx_msg;		/* message context */
};

#ifdef _FFR_REPORT_INTERVALS
/*
**  DKIMF_RIDB_ENTRY -- report interval database entry
*/

struct dkimf_ridb_entry
{
	u_long			ridb_count;
	time_t			ridb_start;
};
#endif /* _FFR_REPORT_INTERVALS */

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

#define	ADSPDENYSMTP		"550"
#define	ADSPDENYESC		"5.7.1"
#define	ADSPDENYTEXT		"rejected due to DKIM ADSP evaluation"

#define	ADSPNXDOMAINSMTP	"550"
#define	ADSPNXDOMAINESC		"5.7.1"
#define	ADSPNXDOMAINTEXT	"sender domain does not exist"

#ifdef _FFR_DKIM_REPUTATION
# define REPDENYSMTP		"550"
# define REPDENYESC		"5.7.1"
# define REPDENYTXT		"rejected due to DKIM reputation evaluation"
#endif /* _FFR_DKIM_REPUTATION */

#define	DELIMITER		"\001"

struct lookup dkimf_params[] =
{
	{ "no",			HNDL_NOSIGNATURE },
	{ "nosignature",	HNDL_NOSIGNATURE },
	{ "bad",		HNDL_BADSIGNATURE },
	{ "badsignature",	HNDL_BADSIGNATURE },
	{ "dns",		HNDL_DNSERROR },
	{ "dnserror",		HNDL_DNSERROR },
	{ "int",		HNDL_INTERNAL },
	{ "internal",		HNDL_INTERNAL },
	{ "sec",		HNDL_SECURITY },
	{ "security",		HNDL_SECURITY },
	{ "def",		HNDL_DEFAULT },
	{ "default",		HNDL_DEFAULT },
	{ NULL,			-1 },
};

struct lookup dkimf_values[] =
{
	{ "a",			SMFIS_ACCEPT },
	{ "accept",		SMFIS_ACCEPT },
	{ "d",			SMFIS_DISCARD },
	{ "discard",		SMFIS_DISCARD },
	{ "r",			SMFIS_REJECT },
	{ "reject",		SMFIS_REJECT },
	{ "t",			SMFIS_TEMPFAIL },
	{ "tempfail",		SMFIS_TEMPFAIL },
	{ NULL,			-1 },
};

struct lookup dkimf_canon[] =
{
	{ "relaxed",		DKIM_CANON_RELAXED },
	{ "simple",		DKIM_CANON_SIMPLE },
	{ NULL,			-1 },
};

struct lookup dkimf_policy[] =
{
	{ "unknown",		DKIM_POLICY_UNKNOWN },
	{ "all",		DKIM_POLICY_ALL },
	{ "discardable",	DKIM_POLICY_DISCARDABLE },
	{ NULL,			-1 },
};

struct lookup dkimf_sign[] =
{
	{ "rsa-sha1",		DKIM_SIGN_RSASHA1 },
#ifdef SHA256_DIGEST_LENGTH
	{ "rsa-sha256",		DKIM_SIGN_RSASHA256 },
#endif /* SHA256_DIGEST_LENGTH */
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
struct lookup dkimf_dnssec[] =
{
	{ "unknown",		DKIM_DNSSEC_UNKNOWN },
	{ "bogus",		DKIM_DNSSEC_BOGUS },
	{ "insecure",		DKIM_DNSSEC_INSECURE },
	{ "secure",		DKIM_DNSSEC_SECURE },
	{ NULL,			-1 },
};

#define	DKIM_KEYACTIONS_NONE	0
#define	DKIM_KEYACTIONS_NEUTRAL	1
#define	DKIM_KEYACTIONS_FAIL	2

struct lookup dkimf_keyactions[] =
{
	{ "none",		DKIM_KEYACTIONS_NONE },
	{ "neutral",		DKIM_KEYACTIONS_NEUTRAL },
	{ "fail",		DKIM_KEYACTIONS_FAIL },
	{ NULL,			-1 },
};

#define	DKIM_POLICYACTIONS_IGNORE	0
#define DKIM_POLICYACTIONS_APPLY	1

struct lookup dkimf_policyactions[] =
{
	{ "ignore",		DKIM_POLICYACTIONS_IGNORE },
	{ "apply",		DKIM_POLICYACTIONS_APPLY },
	{ NULL,			-1 },
};
#endif /* USE_UNBOUND */

/* default internal list */
char *defilist[] =
{
	"127.0.0.1",
	NULL
};

#ifdef _FFR_COMMAIZE
/*
**  List of header fields that the MTA might rewrite, taken from
**  sendmail/conf.c
*/

char *commaize_hdrs[] =
{
	/* sender headers */
	"resent-sender",
	"resent-from",
	"resent-reply-to",
	"sender",
	"from",
	"reply-to",
	"errors-to",
	"disposition-notification-to",

	/* recipient headers */
	"to",
	"resent-to",
	"cc",
	"resent-cc",
	"bcc",
	"resent-bcc",
	"apparently-to",

	/* end */
	NULL
};
#endif /* _FFR_COMMAIZE */

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

static void dkimf_cleanup __P((SMFICTX *));
static void dkimf_config_reload __P((void));
static Header dkimf_findheader __P((msgctx, char *, int));
void *dkimf_getpriv __P((SMFICTX *));
char * dkimf_getsymval __P((SMFICTX *, char *));
sfsistat dkimf_insheader __P((SMFICTX *, int, char *, char *));
static int dkimf_loadkeys __P((char *, struct dkimf_config *));
static void dkimf_freekeys __P((struct dkimf_config *));
static void dkimf_policyreport __P((msgctx, struct dkimf_config *, char *));
void dkimf_sendprogress __P((void *));
sfsistat dkimf_setpriv __P((SMFICTX *, void *));
sfsistat dkimf_setreply __P((SMFICTX *, char *, char *, char *));
static void dkimf_sigreport __P((msgctx, struct dkimf_config *, char *));

/* GLOBALS */
_Bool dolog;					/* logging? (exported) */
_Bool reload;					/* reload requested */
_Bool no_i_whine;				/* noted ${i} is undefined */
_Bool quarantine;				/* quarantine failures? */
_Bool testmode;					/* test mode */
#ifdef QUERY_CACHE
_Bool querycache;				/* local query cache */
#endif /* QUERY_CACHE */
_Bool die;					/* global "die" flag */
int diesig;					/* signal to distribute */
int thread_count;				/* thread count */
#ifdef QUERY_CACHE
time_t cache_lastlog;				/* last cache stats logged */
#endif /* QUERY_CACHE */
#if VERIFY_DOMAINKEYS
DK_LIB *libdk;					/* libdk handle */
#endif /* VERIFY_DOMAINKEYS */
char *progname;					/* program name */
char *sock;					/* listening socket */
char *conffile;					/* configuration file */
struct dkimf_config *curconf;			/* current configuration */
#if POPAUTH
DB *popdb;					/* POP auth DB */
#endif /* POPAUTH */
#ifdef _FFR_BODYLENGTH_DB
DB *bldb;					/* DB of rcpts to receive l= */
pthread_mutex_t bldb_lock;			/* bldb lock */
#endif /* _FFR_BODYLENGTH_DB */
#ifdef _FFR_REPORT_INTERVALS
DB *ridb;					/* report intervals DB */
pthread_mutex_t ridb_lock;			/* ridb lock */
#endif /* _FFR_REPORT_INTERVALS */
char reportaddr[MAXADDRESS + 1];		/* reporting address */
pthread_mutex_t conf_lock;			/* config lock */
pthread_mutex_t count_lock;			/* counter lock */
pthread_mutex_t popen_lock;			/* popen() lock */

/* Other useful definitions */
#define CRLF			"\r\n"		/* CRLF */

#ifndef SENDMAIL_OPTIONS
# define SENDMAIL_OPTIONS	""		/* options for reports */
#endif /* SENDMAIL_OPTIONS */

/* MACROS */
#define	JOBID(x)	((x) == NULL ? JOBIDUNKNOWN : (x))
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

#if NO_SMFI_INSHEADER
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
#endif /* NO_SMFI_INSHEADER */

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
		return smfi_insheader(ctx, idx, hname, hvalue);
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

		list[which] = t;
		idx++;

		return TRUE;
	}
}


#ifdef _FFR_REPORT_INTERVALS
/*
**  DKIMF_RIDB_CHECK -- determine if a report should be sent or not
**
**  Parameters:
**  	domain -- domain to report
**  	interval -- reporting interval
**
**  Return value:
**  	>1 -- yes, send a report; return value indicates how many incidents
**  	      that report represents
**  	0 -- no, don't send a report
**  	-1 -- error
*/

static int
dkimf_ridb_check(char *domain, unsigned int interval)
{
	_Bool exists;
	int status;
	size_t ris;
	struct dkimf_ridb_entry ri;

	assert(domain != NULL);

	/* an interval of 0 means "send now" */
	if (interval == 0)
		return 1;

	ris = sizeof ri;
	status = dkimf_db_get(ridb, domain, &ri, &ris, &exists, &ridb_lock);

	if (status == 0)
	{
		time_t now;

		(void) time(&now);

		if (!exists)					/* new */
		{
			ri.ridb_start = now;
			ri.ridb_count = 1;

			status = dkimf_db_put(ridb, domain, &ri, sizeof ris,
			                      &ridb_lock);

			if (status != 0)
				return -1;

			return 0;
		}
		else if (ri.ridb_start + interval > now)	/* update */
		{
			ri.ridb_count++;

			status = dkimf_db_put(ridb, domain, &ri, sizeof ris,
			                      &ridb_lock);

			if (status != 0)
				return -1;

			return 0;
		}
		else						/* delete */
		{
			status = dkimf_db_delete(ridb, domain, &ridb_lock);

			if (status != 0)
				return -1;

			return ++ri.ridb_count;
		}
	}
	else
	{
		return -1;
	}
}
#endif /* _FFR_REPORT_INTERVALS */

#ifdef _FFR_MULTIPLE_SIGNATURES
/*
**  DKIMF_ADD_SIGNREQUEST -- add a signing request
**
**  Parameters:
**  	dfc -- DKIM filter context
**  	key -- keytable entry
**
**  Return value:
**  	TRUE iff the list was updated.
*/

static _Bool
dkimf_add_signrequest(msgctx dfc, struct keytable *key)
{
	struct signreq *new;

	assert(dfc != NULL);
	assert(key != NULL);

	new = malloc(sizeof *new);
	if (new == NULL)
		return FALSE;

	new->srq_key = key;
	new->srq_next = NULL;
	new->srq_dkim = NULL;

	if (dfc->mctx_srtail != NULL)
		dfc->mctx_srtail->srq_next = new;
	else
		dfc->mctx_srtail = new;

	if (dfc->mctx_srhead == NULL)
		dfc->mctx_srhead = new;

	return TRUE;
}

/*
**  DKIMF_MSR_HEADER -- process headers for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**  	header -- header field name and value
**  	headerlen -- number of bytes at "header"
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_header(struct signreq *sr, u_char *header, size_t headerlen)
{
	DKIM_STAT status;

	assert(sr != NULL);
	assert(header != NULL);

	while (sr != NULL)
	{
		status = dkim_header(sr->srq_dkim, header, headerlen);
		if (status != DKIM_STAT_OK)
			return status;
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_MSR_EOH -- process end-of-headers for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_eoh(struct signreq *sr)
{
	DKIM_STAT status;

	assert(sr != NULL);

	while (sr != NULL)
	{
		status = dkim_eoh(sr->srq_dkim);
		if (status != DKIM_STAT_OK)
			return status;
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}

/*
**  DKIMF_MSR_BODY -- process a body chunk for multiple signing requests
**
**  Parameters:
**  	srh -- head of the signature request list
**  	body -- body chunk
**  	bodylen -- body length
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_body(struct signreq *sr, u_char *body, size_t bodylen)
{
	DKIM_STAT status;

	assert(sr != NULL);
	assert(body != NULL);

	while (sr != NULL)
	{
		status = dkim_body(sr->srq_dkim, body, bodylen);
		if (status != DKIM_STAT_OK)
			return status;
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
**
**  Return value:
**  	A DKIM_STAT_* constant, either DKIM_STAT_OK if all of them passed
**  	or some other constant if one of them failed.
*/

static DKIM_STAT
dkimf_msr_eom(struct signreq *sr)
{
	_Bool testkey;
	DKIM_STAT status;

	assert(sr != NULL);

	while (sr != NULL)
	{
		status = dkim_eom(sr->srq_dkim, &testkey);
		if (status != DKIM_STAT_OK)
			return status;
		sr = sr->srq_next;
	}

	return DKIM_STAT_OK;
}
#endif /* _FFR_MULTIPLE_SIGNATURES */

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

	/* ignore signatures which are neither first-party nor trusted */
	for (c = 0; c < nsigs; c++)
	{
		sdomain = dkim_sig_getdomain(sigs[c]);

		/* author domain */
		if (strcasecmp((char *) sdomain, (char *) domain) == 0)
			continue;

		/* trusted third party domain */
		if (conf->conf_thirdparty != NULL)
		{
			_Bool found = FALSE;
			int d;

			for (d = 0; conf->conf_thirdparty[d] != NULL; d++)
			{
				if (strcasecmp(conf->conf_thirdparty[d],
				               (char *) sdomain) == 0)
				{
					found = TRUE;
					break;
				}
			}

			if (found)
				continue;
		}

		/* neither; arrange to ignore it */
		dkim_sig_ignore(sigs[c]);

		if (conf->conf_dolog)
		{
			syslog(LOG_INFO, "%s ignoring signature from %s",
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
		return ARF_TYPE_DKIM;
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

	sig = dkim_getsignature(dfc->mctx_dkim);
	if (sig == NULL)
		return ARF_DKIMF_UNKNOWN;

	if (dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
		return ARF_DKIMF_BODYHASH;

	switch (dkim_sig_geterror(sig))
	{
	  case DKIM_SIGERROR_BADSIG:
		return ARF_DKIMF_SIGNATURE;

	  case DKIM_SIGERROR_GRANULARITY:
		return ARF_DKIMF_GRANULARITY;

	  case DKIM_SIGERROR_KEYREVOKED:
		return ARF_DKIMF_REVOKED;

	  case DKIM_SIGERROR_VERSION:
	  case DKIM_SIGERROR_MISSING_C:
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
	assert(conf != NULL);

	if (conf->conf_reportaddr != NULL)
	{
		strlcpy(reportaddr, conf->conf_reportaddr,
		           sizeof reportaddr);
	}
	else
	{
		uid_t uid;
		struct passwd *pw;
		char hostname[DKIM_MAXHOSTNAMELEN + 1];

		(void) gethostname(hostname, sizeof hostname);

		uid = geteuid();

		pw = getpwuid(uid);

		if (pw == NULL)
		{
			snprintf(reportaddr, sizeof reportaddr,
			         "%u@%s", uid, hostname);
		}
		else
		{
			snprintf(reportaddr, sizeof reportaddr,
			         "%s@%s", pw->pw_name, hostname);
		}
	}
}

/*
**  DKIMF_CONFIGLOOKUP -- look up the integer code for a config option or value
**
**  Parameters:
**  	opt -- option to look up
**  	table -- lookup table to use
**
**  Return value:
**  	Integer version of the option, or -1 on error.
*/

static int
dkimf_configlookup(char *opt, struct lookup *table)
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
**  DKIMF_LOCAL_ADSP -- check for a local ADSP assertion
**
**  Parameters:
**  	conf -- configuration handle to check
**  	domain -- domain to evaluate
**  	pcode -- policy code (returned)
**
**  Return value:
**  	1 -- match, "pcode" updated
**  	0 -- no match, "pcode" unchanged
*/

static int
dkimf_local_adsp(struct dkimf_config *conf, char *domain, dkim_policy_t *pcode)
{
	assert(conf != NULL);
	assert(domain != NULL);
	assert(pcode != NULL);

	if (conf->conf_localadsp_domain != NULL)
	{
		int c;
		char *policy = NULL;

		for (c = 0; conf->conf_localadsp_domain[c] != NULL; c++)
		{
			if (strcasecmp(domain,
			               conf->conf_localadsp_domain[c]) == 0)
			{
				policy = conf->conf_localadsp_policy[c];
				break;
			}

			if (dkimf_subdomain(domain,
			                    conf->conf_localadsp_domain[c]))
			{
				policy = conf->conf_localadsp_policy[c];
				break;
			}

			if (policy != NULL)
				break;
		}

		if (policy != NULL)
		{
			dkim_policy_t tmpp;

			tmpp = dkimf_configlookup(policy, dkimf_policy);
			if (tmpp != -1)
			{
				*pcode = tmpp;
				return 1;
			}
		}
	}

	return 0;
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
		return cc->cctx_msg->mctx_dkim;
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
	else if (sig == SIGUSR1)
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

	if (conf->conf_keyhead != NULL)
	{
		struct keytable *key;
		struct keytable *next;

		key = conf->conf_keyhead;
		while (key != NULL)
		{
			next = key->key_next;

			memset(key->key_data, '\0', key->key_len);
			free(key->key_data);
			free(key->key_domain);
			free(key);

			key = next;
		}

		conf->conf_keyhead = NULL;
		conf->conf_keytail = NULL;
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

	status = dkim_getsiglist(msg->mctx_dkim, &sigs, &nsigs);
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
**  DKIMF_PARSECONFIG -- parse message handling configuration and/or
**                       apply defaults
**
**  Parameters:
** 	confstr -- configuration string, or NULL to apply defaults only
**  	conf -- configuration handle to update
**
**  Return value:
**  	TRUE on success, FALSE on failure.
*/

static _Bool
dkimf_parseconfig(char *confstr, struct dkimf_config *conf)
{
	int vs;
	char *p;
	char *v;
	char *tmp;

	if (confstr == NULL)
		return TRUE;

	tmp = strdup(confstr);
	if (tmp == NULL)
	{
		fprintf(stderr, "%s: strdup(): %s\n", progname,
		        strerror(errno));
		return FALSE;
	}

	/* process configuration */
	for (p = strtok(tmp, ","); p != NULL; p = strtok(NULL, ","))
	{
		v = strchr(p, '=');
		if (v == NULL)
		{
			fprintf(stderr,
			        "%s: syntax error in configuration string\n",
			        progname);
			return FALSE;
		}
		*v = '\0';
		v++;

		vs = dkimf_configlookup(v, dkimf_values);
		if (vs == -1)
		{
			fprintf(stderr,
			        "%s: invalid configuration value `%s'\n",
			        progname, v);
			return FALSE;
		}

		/* apply what's been found */
		switch (dkimf_configlookup(p, dkimf_params))
		{
		  case HNDL_NOSIGNATURE:
			conf->conf_handling.hndl_nosig = vs;
			break;

		  case HNDL_BADSIGNATURE:
			conf->conf_handling.hndl_badsig = vs;
			break;

		  case HNDL_DNSERROR:
			conf->conf_handling.hndl_dnserr = vs;
			break;

		  case HNDL_INTERNAL:
			conf->conf_handling.hndl_internal = vs;
			break;

		  case HNDL_SECURITY:
			conf->conf_handling.hndl_security = vs;
			break;

		  case HNDL_DEFAULT:
			conf->conf_handling.hndl_nosig = vs;
			conf->conf_handling.hndl_badsig = vs;
			conf->conf_handling.hndl_dnserr = vs;
			conf->conf_handling.hndl_internal = vs;
			conf->conf_handling.hndl_security = vs;
			break;

		  default:
			*v = '=';
			fprintf(stderr,
			        "%s: invalid configuration parameter `%s'\n",
			        progname, p);
			return FALSE;
		}
	}

	return TRUE;
}

/*
**  DKIMF_PARSECONFIG2 -- parse a single configuration value
**
**  Parameters:
**  	cfg -- pointer to data loaded from a configuration file
**  	name -- name of the parameter to query
**  	code -- equivalent code for the -C option
**  	str -- string to update
**  	len -- size of "str"
**
**  Return value:
**  	None.
**
**  Notes:
**  	This is transitional, for use during the time that the -C option
**  	and the configuration file coexist.  The -C option overrides
**  	the values found in the file.
*/

static void
dkimf_parseconfig2(struct config *cfg, const char *name, const char *code,
                   char *str, size_t len)
{
	char *v;
	size_t offset;

	assert(cfg != NULL);
	assert(name != NULL);
	assert(code != NULL);
	assert(str != NULL);
	assert(len > 0);

	if (config_get(cfg, name, &v, sizeof(char *)) == 1)
	{
		offset = strlen(str);

		snprintf(str + offset, len - offset, "%s%s=%s",
		         offset == 0 ? "" : ",", code, v);
	}
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
	new->conf_maxhdrsz = DEFMAXHDRSZ;
	new->conf_signbytes = -1L;
	new->conf_sigmintype = SIGMIN_BYTES;
#ifdef _FFR_DKIM_REPUTATION
	new->conf_repreject = DKIM_REP_DEFREJECT;
#endif /* _FFR_DKIM_REPUTATION */

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

	if (conf->conf_domains != NULL)
		free(conf->conf_domains);

	if (conf->conf_domlist != NULL)
		free(conf->conf_domlist);

	if (conf->conf_omithdrs != NULL)
		free(conf->conf_omithdrs);

	if (conf->conf_signhdrs != NULL)
		free(conf->conf_signhdrs);

	if (conf->conf_alwayshdrs != NULL)
		free(conf->conf_alwayshdrs);

	if (conf->conf_senderhdrs != NULL &&
	    conf->conf_senderhdrs != (char **) default_senderhdrs)
		free(conf->conf_senderhdrs);

	if (conf->conf_mtas != NULL)
		free(conf->conf_mtas);

	if (conf->conf_mtalist != NULL)
		free(conf->conf_mtalist);

	if (conf->conf_macrolist != NULL)
		free(conf->conf_macrolist);

	if (conf->conf_macros != NULL)
		free(conf->conf_macros);

	if (conf->conf_values != NULL)
		free(conf->conf_values);

	if (conf->conf_mbs != NULL)
		free(conf->conf_mbs);

	if (conf->conf_dontsignto != NULL)
		free(conf->conf_dontsignto);

#ifdef _FFR_DKIM_REPUTATION
	if (conf->conf_reproot != NULL)
		free(conf->conf_reproot);
#endif /* _FFR_DKIM_REPUTATION */

	if (conf->conf_authservid != NULL)
		free(conf->conf_authservid);

	if (conf->conf_peerlist != NULL)
		dkimf_free_list(conf->conf_peerlist);

	if (conf->conf_internal != NULL)
		dkimf_free_list(conf->conf_internal);

	if (conf->conf_exignore != NULL)
		dkimf_free_list(conf->conf_exignore);

	dkimf_freekeys(conf);

#ifdef _FFR_REPLACE_RULES
	if (conf->conf_replist != NULL)
		dkimf_free_replist(conf->conf_replist);
#endif /* _FFR_REPLACE_RULES */

#ifdef _FFR_VBR
	if (conf->conf_vbr_trusted != NULL)
		free(conf->conf_vbr_trusted);
#endif /* _FFR_VBR */

	if (conf->conf_dompats != NULL)
	{
		int n;

		for (n = 0; conf->conf_dompats[n] != NULL; n++)
			regfree(conf->conf_dompats[n]);

		free(conf->conf_dompats);
	}

	if (conf->conf_nosignpats != NULL)
	{
		int n;

		for (n = 0; conf->conf_nosignpats[n] != NULL; n++)
			regfree(conf->conf_nosignpats[n]);

		free(conf->conf_nosignpats);
	}

	if (conf->conf_localadsp_domain != NULL)
	{
		int n;

		for (n = 0; conf->conf_localadsp_domain[n] != NULL; n++)
			free(conf->conf_localadsp_domain[n]);

		free(conf->conf_localadsp_domain);
		free(conf->conf_localadsp_policy);
	}

	config_free(conf->conf_data);

	free(conf);
}

/*
**  DKIMF_CONFIG_LOAD -- load a configuration handle based on file content
**
**  Paramters:
**  	data -- configuration data loaded from config file
**  	conf -- configuration structure to load
**  	err -- where to write errors
**  	errlen -- bytes available at "err"
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
                  char *err, size_t errlen)
{
	int maxsign;
	char *str;
	char confstr[BUFRSZ + 1];
	char basedir[MAXPATHLEN + 1];

	assert(conf != NULL);

	memset(basedir, '\0', sizeof basedir);

	if (data != NULL)
	{
		(void) config_get(data, "AlwaysAddARHeader",
		                  &conf->conf_alwaysaddar,
		                  sizeof conf->conf_alwaysaddar);

		str = NULL;
		(void) config_get(data, "AuthservID", &str, sizeof str);
		if (str != NULL)
			conf->conf_authservid = strdup(str);

		(void) config_get(data, "AuthservIDWithJobID",
		                  &conf->conf_authservidwithjobid,
		                  sizeof conf->conf_authservidwithjobid);

		(void) config_get(data, "BaseDirectory", basedir,
		                  sizeof basedir);

		(void) config_get(data, "BodyLengths", &conf->conf_blen,
		                  sizeof conf->conf_blen);

		if (conf->conf_canonstr == NULL)
		{
			(void) config_get(data, "Canonicalization",
			                  &conf->conf_canonstr,
			                  sizeof conf->conf_canonstr);
		}

		(void) config_get(data, "ClockDrift", &conf->conf_clockdrift,
		                  sizeof conf->conf_clockdrift);

#ifdef _FFR_COMMAIZE
		(void) config_get(data, "Commaize", &conf->conf_commaize,
		                  sizeof conf->conf_commaize);
#endif /* _FFR_COMMAIZE */

		(void) config_get(data, "Diagnostics", &conf->conf_ztags,
		                  sizeof conf->conf_ztags);

#ifdef _FFR_ZTAGS
		(void) config_get(data, "DiagnosticDirectory",
		                  &conf->conf_diagdir,
		                  sizeof conf->conf_diagdir);
#endif /* _FFR_ZTAGS */

		if (conf->conf_dnstimeout == DEFTIMEOUT)
		{
			(void) config_get(data, "DNSTimeout",
			                  &conf->conf_dnstimeout,
			                  sizeof conf->conf_dnstimeout);
		}

		(void) config_get(data, "EnableCoredumps",
		                  &conf->conf_enablecores,
		                  sizeof conf->conf_enablecores);

		(void) config_get(data, "FixCRLF",
		                  &conf->conf_fixcrlf,
		                  sizeof conf->conf_fixcrlf);

		(void) config_get(data, "KeepTemporaryFiles",
		                  &conf->conf_keeptmpfiles,
		                  sizeof conf->conf_keeptmpfiles);

		(void) config_get(data, "TemporaryDirectory",
		                  &conf->conf_tmpdir,
		                  sizeof conf->conf_tmpdir);

		(void) config_get(data, "MaximumHeaders", &conf->conf_maxhdrsz,
		                  sizeof conf->conf_maxhdrsz);

#ifdef _FFR_DKIM_REPUTATION
		(void) config_get(data, "ReputationFail", &conf->conf_repfail,
		                  sizeof conf->conf_repfail);

		(void) config_get(data, "ReputationPass", &conf->conf_reppass,
		                  sizeof conf->conf_reppass);

		(void) config_get(data, "ReputationReject",
		                  &conf->conf_repreject,
		                  sizeof conf->conf_repreject);

		str = NULL;
		(void) config_get(data, "ReputationRoot", &str, sizeof str);
		if (str != NULL)
			conf->conf_reproot = strdup(str);

		if (conf->conf_repfail < conf->conf_reppass)
		{
			snprintf(err, errlen,
			         "invalid reputation thresholds (ReputationFail < ReputationPass)");
			return -1;
		}

		if (conf->conf_repreject < conf->conf_repfail)
		{
			snprintf(err, errlen,
			         "invalid reputation thresholds (ReputationReject < ReputationFail)");
			return -1;
		}
#endif /* _FFR_DKIM_REPUTATION */

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

		memset(confstr, '\0', sizeof confstr);
		dkimf_parseconfig2(data, "On-Default", "def", confstr,
		                   sizeof confstr);
		dkimf_parseconfig2(data, "On-BadSignature", "bad",
		                   confstr, sizeof confstr);
		dkimf_parseconfig2(data, "On-DNSError", "dns", confstr,
		                   sizeof confstr);
		dkimf_parseconfig2(data, "On-InternalError", "int",
		                   confstr, sizeof confstr);
		dkimf_parseconfig2(data, "On-NoSignature", "no",
		                   confstr, sizeof confstr);
		dkimf_parseconfig2(data, "On-Security", "sec", confstr,
		                   sizeof confstr);

		(void) config_get(data, "RemoveARAll", &conf->conf_remarall,
		                  sizeof conf->conf_remarall);

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

#ifdef _FFR_SELECTOR_HEADER
		(void) config_get(data, "SelectorHeader",
		                  &conf->conf_selectorhdr,
		                  sizeof conf->conf_selectorhdr);
#endif /* _FFR_SELECTOR_HEADER */

		if (!conf->conf_sendreports)
		{
			(void) config_get(data, "SendReports",
			                  &conf->conf_sendreports,
			                  sizeof conf->conf_sendreports);
		}

		(void) config_get(data, "SendADSPReports",
		                  &conf->conf_sendadspreports,
		                  sizeof conf->conf_sendadspreports);

		(void) config_get(data, "ReportAddress",
		                  &conf->conf_reportaddr,
		                  sizeof conf->conf_reportaddr);

		if (conf->conf_signalgstr == NULL)
		{
			(void) config_get(data, "SignatureAlgorithm",
			                  &conf->conf_signalgstr,
			                  sizeof conf->conf_signalgstr);
		}

		(void) config_get(data, "SignatureTTL", &conf->conf_sigttl,
		                  sizeof conf->conf_sigttl);

#ifdef _FFR_STATS
		(void) config_get(data, "Statistics", &conf->conf_statspath,
		                  sizeof conf->conf_statspath);
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

#ifdef _FFR_MULTIPLE_SIGNATURES
		(void) config_get(data, "MultipleSignatures",
		                  &conf->conf_multisig,
		                  sizeof conf->conf_multisig);
#endif /* _FFR_MULTIPLE_SIGNATURES */

		(void) config_get(data, "SyslogSuccess",
		                  &conf->conf_dolog_success,
		                  sizeof conf->conf_dolog_success);

		(void) config_get(data, "ADSPDiscard",
		                  &conf->conf_adspdiscard,
		                  sizeof conf->conf_adspdiscard);

		(void) config_get(data, "ADSPNoSuchDomain",
		                  &conf->conf_adspnxdomain,
		                  sizeof conf->conf_adspnxdomain);

		if (!conf->conf_addxhdr)
		{
			(void) config_get(data, "X-Header",
			                  &conf->conf_addxhdr,
			                  sizeof conf->conf_addxhdr);
		}

		(void) config_get(data, "AllowSHA1Only",
		                  &conf->conf_allowsha1only,
		                  sizeof conf->conf_allowsha1only);
#ifdef USE_UNBOUND
		(void) config_get(data, "TrustAnchorFile",
		                  &conf->conf_trustanchorpath,
		                  sizeof conf->conf_trustanchorpath);

		str = NULL;
		(void) config_get(data, "BogusKey", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_configlookup(str, dkimf_keyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown key action `%s'", str);
				return -1;
			}

			conf->conf_boguskey = c;
		}
		else
		{
			conf->conf_boguskey = DKIM_KEYACTIONS_FAIL;
		}

		str = NULL;
		(void) config_get(data, "InsecureKey", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_configlookup(str, dkimf_keyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown key action `%s'", str);
				return -1;
			}

			conf->conf_insecurekey = c;
		}
		else
		{
			conf->conf_boguskey = DKIM_KEYACTIONS_NONE;
		}

		str = NULL;
		(void) config_get(data, "BogusPolicy", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_configlookup(str, dkimf_policyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown policy action `%s'", str);
				return -1;
			}

			conf->conf_boguspolicy = c;
		}
		else
		{
			conf->conf_boguspolicy = DKIM_POLICYACTIONS_IGNORE;
		}

		str = NULL;
		(void) config_get(data, "InsecurePolicy", &str, sizeof str);
		if (str != NULL)
		{
			int c;

			c = dkimf_configlookup(str, dkimf_policyactions);
			if (c == -1)
			{
				snprintf(err, errlen,
				         "unknown policy action `%s'", str);
				return -1;
			}

			conf->conf_insecurepolicy = c;
		}
		else
		{
			conf->conf_insecurepolicy = DKIM_POLICYACTIONS_APPLY;
		}
#endif /* USE_UNBOUND */
	}

	if (basedir[0] != '\0')
	{
		if (chdir(basedir) != 0)
		{
			snprintf(err, errlen, "%s: chdir(): %s",
			         basedir, strerror(errno));
			return -1;
		}
	}

	if (conf->conf_actions == NULL && confstr[0] != '\0')
		conf->conf_actions = confstr;

	if (conf->conf_actions != NULL &&
	    !dkimf_parseconfig(conf->conf_actions, conf))
	{
		snprintf(err, errlen, "invalid action configuration");
		return -1;
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
		FILE *f;

		f = fopen(str, "r");
		if (f == NULL)
		{
			snprintf(err, errlen, "%s: fopen(): %s",
			         str, strerror(errno));
			return -1;
		}

		if (!dkimf_load_list(f, NULL, &conf->conf_peerlist))
		{
			snprintf(err, errlen,
			         "failed to load Peerlist from %s", str);
			fclose(f);
			return -1;
		}

		fclose(f);
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
	if (str != NULL && !testmode)
	{
		FILE *f;

		f = fopen(str, "r");
		if (f == NULL)
		{
			snprintf(err, errlen, "%s: fopen(): %s",
			         str, strerror(errno));
			return -1;
		}

		if (!dkimf_load_list(f, NULL, &conf->conf_internal))
		{
			snprintf(err, errlen,
			         "failed to load InternalHosts from %s", str);
			fclose(f);
			return -1;
		}

		fclose(f);
	}
	else
	{
		if (!dkimf_load_list(NULL, defilist, &conf->conf_internal))
			return -1;
	}

	/* external ignore list */
	str = NULL;
	if (conf->conf_externalfile != NULL)
	{
		str = conf->conf_externalfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "ExternalIgnoreList", &str, sizeof str);
	}
	if (str != NULL && !testmode)
	{
		FILE *f;

		f = fopen(str, "r");
		if (f == NULL)
		{
			snprintf(err, errlen, "%s: fopen(): %s",
			         str, strerror(errno));
			return -1;
		}

		if (!dkimf_load_list(f, NULL, &conf->conf_exignore))
		{
			snprintf(err, errlen,
			         "failed to load ExternalIgnoreList from %s",
			         str);
			fclose(f);
			return -1;
		}

		fclose(f);
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "SignHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int c;
		size_t len;
		char *p;
		char *last;

		c = 1;
		for (p = str; p != NULL; p = strchr(p + 1, ','))
			c++;

		len = (c + 1) * sizeof(char *);
		conf->conf_signhdrs = malloc(len);
		if (conf->conf_signhdrs == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		memset(conf->conf_signhdrs, '\0', len);
		for (c = 0, p = strtok_r(str, ",", &last);
		     p != NULL;
		     c++, p = strtok_r(NULL, ",", &last))
			conf->conf_signhdrs[c] = p;
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "RemoveARFrom", &str, sizeof str);
	if (str != NULL)
	{
		int n = 1;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		conf->conf_remar = (char **) malloc((n + 1) * sizeof(char *));
		if (conf->conf_remar == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		n = 0;

		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
			conf->conf_remar[n++] = p;

		conf->conf_remar[n] = NULL;
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "DontSignMailTo", &str, sizeof str);
	if (str != NULL)
	{
		_Bool makepats = FALSE;
		int n = 1;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
			if (*p == '*')
				makepats = TRUE;
		}

		conf->conf_dontsignto = (char **) malloc((n + 1) * sizeof(char *));
		if (conf->conf_dontsignto == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		n = 0;

		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
			conf->conf_dontsignto[n++] = p;

		conf->conf_dontsignto[n] = NULL;

		if (makepats)
		{
			size_t len;

			len = (n + 1) * sizeof(regex_t *);
			conf->conf_nosignpats = (regex_t **) malloc(len);
			if (conf->conf_nosignpats == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				return -1;
			}
			else
			{
				int c;
				char patbuf[BUFRSZ + 1];

				memset(conf->conf_nosignpats, '\0', len);

				for (c = 0; c < n; c++)
				{
					conf->conf_nosignpats[c] = (regex_t *) malloc(sizeof(regex_t));
					if (conf->conf_nosignpats[c] == NULL)
					{
						snprintf(err, errlen,
						         "malloc(): %s",
						         strerror(errno));
						return -1;
					}

					if (!dkimf_mkregexp(conf->conf_dontsignto[c],
					                    patbuf, sizeof patbuf))
					{
						snprintf(err, errlen,
						         "can't build regex `%s'",
						         conf->conf_dontsignto[c]);
						return -1;
					}

					if (regcomp(conf->conf_nosignpats[c],
					            patbuf, REG_ICASE) != 0)
					{
						snprintf(err, errlen,
						         "can't compile regex `%s'",
						         conf->conf_dontsignto[c]);
						return -1;
					}
				}
			}
		}
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "MustBeSigned", &str, sizeof str);
	if (str != NULL)
	{
		int n = 1;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		conf->conf_mbs = (char **) malloc((n + 1) * sizeof(char *));
		if (conf->conf_mbs == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		n = 0;

		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
			conf->conf_mbs[n++] = p;

		conf->conf_mbs[n] = NULL;
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
		int n = 1;
		size_t len;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		len = (n + 1) * sizeof(char *);
		conf->conf_omithdrs = (char **) malloc(len);
		if (conf->conf_omithdrs == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}
		
		n = 0;

		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
			   conf->conf_omithdrs[n++] = p;

		conf->conf_omithdrs[n] = NULL;
	}

	str = NULL;
	if (conf->conf_mtalist != NULL)
	{
		str = conf->conf_mtalist;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "MTA", &str, sizeof str);
	}
	if (str != NULL)
	{
		int n = 1;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		conf->conf_mtas = (char **) malloc((n + 1) * sizeof(char *));
		if (conf->conf_mtas == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		n = 0;

		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
			conf->conf_mtas[n++] = p;

		conf->conf_mtas[n] = NULL;
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "AlwaysSignHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int n = 1;
		size_t len;
		char *p;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		len = (n + 1) * sizeof(char *);
		conf->conf_alwayshdrs = (char **) malloc(len);
		if (conf->conf_alwayshdrs == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}
		
		n = 0;

		for (p = strtok(str, ",");
		     p != NULL;
		     p = strtok(NULL, ","))
			   conf->conf_alwayshdrs[n++] = p;

		conf->conf_alwayshdrs[n] = NULL;
	}

	str = NULL;
	if (data != NULL)
		(void) config_get(data, "SenderHeaders", &str, sizeof str);
	if (str != NULL)
	{
		int n = 1;
		size_t len;
		char *p;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		len = (n + 1) * sizeof(char *);
		conf->conf_senderhdrs = (char **) malloc(len);
		if (conf->conf_senderhdrs == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}
		
		n = 0;

		for (p = strtok(str, ",");
		     p != NULL;
		     p = strtok(NULL, ","))
			   conf->conf_senderhdrs[n++] = p;

		conf->conf_senderhdrs[n] = NULL;
	}
	else
	{
		conf->conf_senderhdrs = (char **) default_senderhdrs;
	}

#if _FFR_VBR
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
		int c;
		char *p;
		char *last;

		for (p = str, c = 1; *p != '\0'; p++)
		{
			if (*p == ':' || *p == ',')
				c++;
		}

		conf->conf_vbr_trusted = (char **) malloc(sizeof(char *) * (c + 1));
		if (conf->conf_vbr_trusted == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		for (p = strtok_r(str, ",:", &last), c = 0;
		     p != NULL;
		     p = strtok_r(NULL, ",:", &last), c++)
		{
			conf->conf_vbr_trusted[c] = p;
			conf->conf_vbr_trusted[c + 1] = NULL;
		}
	}
#endif /* _FFR_VBR */

	if (data != NULL)
	{
		if (conf->conf_keyfile == NULL)
		{
			(void) config_get(data, "KeyList", &conf->conf_keyfile,
			                  sizeof conf->conf_keyfile);
			if (conf->conf_keyfile != NULL)
				conf->conf_multikey = TRUE;
		}

		if (conf->conf_keyfile == NULL)
		{
			(void) config_get(data, "KeyFile", &conf->conf_keyfile,
			                  sizeof conf->conf_keyfile);
		}
	}

	str = NULL;
	if (conf->conf_localadsp_file != NULL)
	{
		str = conf->conf_localadsp_file;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "LocalADSP", &str, sizeof str);
	}
	if (str != NULL)
	{
		int c;
		int n;
		int nalloc = 0;
		size_t len;
		FILE *f;
		char *p;
		char line[BUFRSZ + 1];

		n = 0;

		f = fopen(str, "r");
		if (f == NULL)
		{
			snprintf(err, errlen, "%s: fopen(): %s",
			         str, strerror(errno));
			return -1;
		}

		memset(line, '\0', sizeof line);
		while (fgets(line, BUFRSZ, f) != NULL)
		{
			for (p = line; *p != '\0'; p++)
			{
				if (*p == '\n' || *p == '#')
				{
					*p = '\0';
					break;
				}
			}

			dkimf_trimspaces((u_char *) line);
			if (strlen(line) == 0)
				continue;

			if (nalloc <= n)
			{
				if (nalloc == 0)
				{
					len = 2 * sizeof(char *);
					conf->conf_localadsp_domain = (char **) malloc(len);
					nalloc = 1;
				}
				else
				{
					len = (nalloc * 2 + 1) * sizeof(char *);
					conf->conf_localadsp_domain = (char **) realloc(curconf->conf_localadsp_domain,
					                                                len);
					nalloc = nalloc * 2;
				}

				if (conf->conf_localadsp_domain == NULL)
				{
					snprintf(err, errlen,
					         "malloc(): %s",
					         strerror(errno));
					return -1;
				}
			}

			conf->conf_localadsp_domain[n] = strdup(line);
			if (conf->conf_localadsp_domain[n] == NULL)
			{
				snprintf(err, errlen, "strdup(): %s",
				         strerror(errno));
				return -1;
			}

			n++;
		}

		if (conf->conf_localadsp_domain != NULL)
			conf->conf_localadsp_domain[n] = NULL;

		len = (n + 1) * sizeof(char *);
		conf->conf_localadsp_policy = (char **) malloc(len);
		if (conf->conf_localadsp_policy == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		for (c = 0; c < n; c++)
		{
			p = strchr(conf->conf_localadsp_domain[c], ':');
			if (p == NULL)
			{
				conf->conf_localadsp_policy[c] = NULL;
			}
			else
			{
				dkim_policy_t tmpp;

				*p = '\0';

				tmpp = dkimf_configlookup(p + 1, dkimf_policy);
				if (tmpp == (dkim_policy_t) -1)
				{
					snprintf(err, errlen,
					         "unknown ADSP `%s'", p + 1);
					return -1;
				}

				conf->conf_localadsp_policy[c] = p + 1;
			}
		}

		fclose(f);
	}

	str = NULL;
	if (conf->conf_thirdpartyfile != NULL)
	{
		str = conf->conf_thirdpartyfile;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "TrustSignaturesFrom", &str,
		                  sizeof str);
	}
	if (str != NULL)
	{
		int n;

		if (str[0] == '/' && access(str, F_OK) == 0)
		{
			int nalloc = 0;
			size_t len;
			FILE *f;
			char *p;
			char line[BUFRSZ + 1];

			n = 0;

			f = fopen(str, "r");
			if (f == NULL)
			{
				snprintf(err, errlen, "%s: fopen(): %s",
				         str, strerror(errno));
				return -1;
			}

			memset(line, '\0', sizeof line);
			while (fgets(line, BUFRSZ, f) != NULL)
			{
				for (p = line; *p != '\0'; p++)
				{
					if (*p == '\n' || *p == '#')
					{
						*p = '\0';
						break;
					}
				}

				dkimf_trimspaces((u_char *) line);
				if (strlen(line) == 0)
					continue;

				if (nalloc <= n)
				{
					if (nalloc == 0)
					{
						len = 2 * sizeof(char *);
						conf->conf_thirdparty = (char **) malloc(len);
						nalloc = 1;
					}
					else
					{
						len = (nalloc * 2 + 1) * sizeof(char *);
						conf->conf_thirdparty = (char **) realloc(curconf->conf_thirdparty,
						                                          len);
						nalloc = nalloc * 2;
					}

					if (conf->conf_thirdparty == NULL)
					{
						snprintf(err, errlen,
						         "malloc(): %s",
						         strerror(errno));
						return -1;
					}
				}

				conf->conf_thirdparty[n] = strdup(line);
				if (conf->conf_thirdparty[n] == NULL)
				{
					snprintf(err, errlen, "strdup(): %s",
					         strerror(errno));
					return -1;
				}

				n++;
			}

			if (conf->conf_thirdparty != NULL)
				conf->conf_thirdparty[n] = NULL;

			fclose(f);
		}
		else
		{
			size_t len;
			char *p;

			n = 1;

			for (p = str; *p != '\0'; p++)
			{
				if (*p == ',')
					n++;
			}

			len = (n + 1) * sizeof(char *);
			conf->conf_thirdparty = (char **) malloc(len);
			if (conf->conf_thirdparty == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				return -1;
			}

			n = 0;

			for (p = strtok(str, ",");
			     p != NULL;
			     p = strtok(NULL, ","))
			{
				conf->conf_thirdparty[n] = p;
				n++;
			}

			conf->conf_thirdparty[n] = NULL;
		}
	}

	str = NULL;
	if (conf->conf_domlist != NULL)
	{
		str = conf->conf_domlist;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "Domain", &str, sizeof str);
	}
	if (str != NULL)
	{
		int n;

		_Bool makepats = FALSE;

		if (str[0] == '/' && access(str, F_OK) == 0)
		{
			int nalloc = 0;
			size_t len;
			FILE *f;
			char *p;
			char line[BUFRSZ + 1];

			n = 0;

			f = fopen(str, "r");
			if (f == NULL)
			{
				snprintf(err, errlen, "%s: fopen(): %s",
				         str, strerror(errno));
				return -1;
			}

			memset(line, '\0', sizeof line);
			while (fgets(line, BUFRSZ, f) != NULL)
			{
				for (p = line; *p != '\0'; p++)
				{
					if (*p == '\n' || *p == '#')
					{
						*p = '\0';
						break;
					}
				}

				dkimf_trimspaces((u_char *) line);
				if (strlen(line) == 0)
					continue;

				if (nalloc <= n)
				{
					if (nalloc == 0)
					{
						len = 2 * sizeof(char *);
						conf->conf_domains = (char **) malloc(len);
						nalloc = 1;
					}
					else
					{
						len = (nalloc * 2 + 1) * sizeof(char *);
						conf->conf_domains = (char **) realloc(curconf->conf_domains,
						                                       len);
						nalloc = nalloc * 2;
					}

					if (conf->conf_domains == NULL)
					{
						snprintf(err, errlen,
						         "malloc(): %s",
						         strerror(errno));
						return -1;
					}
				}

				conf->conf_domains[n] = strdup(line);
				if (conf->conf_domains[n] == NULL)
				{
					snprintf(err, errlen,
					         "strdup(): %s",
					         strerror(errno));
					return -1;
				}

				if (strchr(curconf->conf_domains[n],
				           '*') != NULL)
					makepats = TRUE;

				n++;
			}

			if (conf->conf_domains != NULL)
				conf->conf_domains[n] = NULL;

			fclose(f);
		}
		else
		{
			size_t len;
			char *p;

			n = 1;

			for (p = str; *p != '\0'; p++)
			{
				if (*p == ',')
					n++;
			}

			len = (n + 1) * sizeof(char *);
			conf->conf_domains = (char **) malloc(len);
			if (conf->conf_domains == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				return -1;
			}

			n = 0;

			for (p = strtok(str, ",");
			     p != NULL;
			     p = strtok(NULL, ","))
			{
				conf->conf_domains[n] = p;

				if (strchr(conf->conf_domains[n], '*') != NULL)
					makepats = TRUE;

				n++;
			}

			conf->conf_domains[n] = NULL;
		}

		if (makepats)
		{
			int c;
			int status;
			size_t len;
			char *end;
			char patbuf[BUFRSZ + 1];

			len = (n + 1) * sizeof(regex_t *);
			conf->conf_dompats = (regex_t **) malloc (len);
			if (conf->conf_dompats == NULL)
			{
				snprintf(err, errlen, "malloc(): %s",
				         strerror(errno));
				return -1;
			}
			memset(conf->conf_dompats, '\0', len);

			for (c = 0; c < n; c++)
			{
				memset(patbuf, '\0', sizeof patbuf);
				end = patbuf + sizeof patbuf;
				patbuf[0] = '^';

				if (!dkimf_mkregexp(conf->conf_domains[c],
				                    patbuf, sizeof patbuf))
				{
					snprintf(err, errlen,
					         "regular expression for \"%s\" too long",
					         conf->conf_domains[c]);
					return -1;
				}

				conf->conf_dompats[c] = (regex_t *) malloc(sizeof(regex_t));
				if (conf->conf_dompats[c] == NULL)
				{
					snprintf(err, errlen, "malloc(): %s",
					         strerror(errno));
					return -1;
				}

				status = regcomp(conf->conf_dompats[c],
				                 patbuf,
				                 (REG_EXTENDED|REG_ICASE));
				if (status != 0)
				{
					char rerr[BUFRSZ + 1];

					memset(rerr, '\0', sizeof rerr);
					(void) regerror(status,
					                conf->conf_dompats[c],
					                rerr, sizeof rerr);

					snprintf(err, errlen, "regcomp(): %s",
					         rerr);

					return -1;
				}
			}
		}
	}

	str = NULL;
	if (conf->conf_macrolist != NULL)
	{
		str = conf->conf_macrolist;
	}
	else if (data != NULL)
	{
		(void) config_get(data, "MacroList", &str, sizeof str);
	}
	if (str != NULL)
	{
		int n = 1;
		char *p;
		char *last;

		for (p = str; *p != '\0'; p++)
		{
			if (*p == ',')
				n++;
		}

		conf->conf_macros = (char **) malloc((n + 1) * sizeof(char *));
		conf->conf_values = (char **) malloc((n + 1) * sizeof(char *));

		if (conf->conf_macros == NULL || conf->conf_values == NULL)
		{
			snprintf(err, errlen, "malloc(): %s", strerror(errno));
			return -1;
		}

		n = 0;
		for (p = strtok_r(str, ",", &last);
		     p != NULL;
		     p = strtok_r(NULL, ",", &last))
		{
			conf->conf_macros[n] = p;
			conf->conf_values[n] = strchr(p, '=');
			if (conf->conf_values[n] != NULL)
			{
				*(conf->conf_values[n]) = '\0';
				conf->conf_values[n] += 1;
			}
			n++;
		}
		conf->conf_macros[n] = NULL;
		conf->conf_values[n] = NULL;
	}

	if (conf->conf_signalgstr != NULL)
	{
		conf->conf_signalg = dkimf_configlookup(conf->conf_signalgstr,
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
			conf->conf_hdrcanon = dkimf_configlookup(conf->conf_canonstr,
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

			conf->conf_hdrcanon = dkimf_configlookup(conf->conf_canonstr,
			                                         dkimf_canon);
			if (conf->conf_hdrcanon == -1)
			{
				snprintf(err, errlen,
				         "unknown canonicalization algorithm \"%s\"",
				         conf->conf_canonstr);
				return -1;
			}

			conf->conf_bodycanon = dkimf_configlookup(p + 1,
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

#ifndef DKIM_SIGN_RSASHA256
	if ((conf->conf_mode & DKIMF_MODE_VERIFIER) != 0)
	{
		if (conf->conf_allowsha1only)
		{
			if (dolog)
			{
				syslog(LOG_WARNING,
				       "verifier mode operating without rsa-sha256 support");
			}
		}
		else
		{
			snprintf(err, errlen,
			         "verify mode requires rsa-sha256 support");
			return -1;
		}
	}
#endif /* ! DKIM_SIGN_RSASHA256 */

#ifdef _FFR_REPLACE_RULES
	/* replacement list */
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

	dkimf_reportaddr(conf);

	/* load the secret key, if one was specified */
	if (conf->conf_keyfile != NULL && conf->conf_multikey)
	{
		int status;

		status = dkimf_loadkeys(conf->conf_keyfile, conf);

		if (status != 0)
		{
			snprintf(err, errlen, "key load from %s failed",
			         conf->conf_keyfile);
			return -1;
		}

		if (conf->conf_keyhead == NULL)
		{
			snprintf(err, errlen, "no keys loaded from %s",
			         conf->conf_keyfile);
			return -1;
		}
	}
	else if (conf->conf_keyfile != NULL)
	{
		int status;
		int fd;
		ssize_t rlen;
		u_char *s33krit;
		struct stat s;

		status = stat(conf->conf_keyfile, &s);
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
			free(s33krit);
			return -1;
		}

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

	if ((conf->conf_mode & DKIMF_MODE_SIGNER) != 0 &&
	    ((conf->conf_multikey && conf->conf_keyfile == NULL) ||
	     (!conf->conf_multikey && (conf->conf_keyfile == NULL ||
	                               conf->conf_selector == NULL))))
	{
		snprintf(err, errlen,
		         "at least one selector and key required for signing mode");
		return -1;
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
**  DKIMF_CONFIG_SETLIB -- set library options based on configuration file
**
**  Parameters:
**  	conf -- DKIM filter configuration data
**
**  Return value:
**  	TRUE on success, FALSE otherwise.
*/

static _Bool
dkimf_config_setlib(struct dkimf_config *conf)
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
			return FALSE;

		conf->conf_libopendkim = lib;
	}

	(void) dkim_options(lib, DKIM_OP_GETOPT, DKIM_OPTS_FLAGS,
	                    &opts, sizeof opts);
	opts |= DKIM_LIBFLAGS_ACCEPTV05;
#ifdef QUERY_CACHE
	if (querycache)
	{
		opts |= DKIM_LIBFLAGS_CACHE;
		(void) time(&cache_lastlog);
	}
#endif /* QUERY_CACHE */
	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
	                    &opts, sizeof opts);

#if USE_ARLIB
	/* set the DNS callback */
	(void) dkim_set_dns_callback(lib, dkimf_sendprogress, CBINTERVAL);
#endif /* USE_ARLIB */

#ifdef USE_UNBOUND
	if (conf->conf_trustanchorpath != NULL)
	{
		status = dkim_set_trust_anchor(lib,
		                               conf->conf_trustanchorpath);
		if (status != DKIM_STAT_OK)
			return FALSE;
	}
#endif /* USE_UNBOUND */

	(void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_TIMEOUT,
	                    &conf->conf_dnstimeout,
	                    sizeof conf->conf_dnstimeout);

	if (conf->conf_clockdrift != 0)
	{
		time_t drift = (time_t) conf->conf_clockdrift;

		status = dkim_options(lib, DKIM_OP_SETOPT,
		                      DKIM_OPTS_CLOCKDRIFT, &drift,
		                      sizeof drift);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_sigttl != 0)
	{
		time_t sigtime = (time_t) conf->conf_sigttl;

		status = dkim_options(lib, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNATURETTL, &sigtime,
		                      sizeof sigtime);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_sendreports || conf->conf_keeptmpfiles ||
	    conf->conf_blen || conf->conf_ztags || conf->conf_fixcrlf)
	{
		u_int opts;

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_GETOPT,
		                      DKIM_OPTS_FLAGS, &opts, sizeof opts);

		if (status != DKIM_STAT_OK)
			return FALSE;

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

		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_FLAGS, &opts, sizeof opts);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_alwayshdrs != NULL)
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_ALWAYSHDRS,
		                      conf->conf_alwayshdrs,
		                      sizeof conf->conf_alwayshdrs);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_mbs != NULL)
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_MUSTBESIGNED,
		                      conf->conf_mbs, sizeof conf->conf_mbs);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_omithdrs != NULL)
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SKIPHDRS,
		                      conf->conf_omithdrs,
		                      sizeof conf->conf_omithdrs);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}
	else
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SKIPHDRS,
		                      (void *) should_not_signhdrs,
		                      sizeof (u_char **));

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_signhdrs != NULL)
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNHDRS, conf->conf_signhdrs,
		                      sizeof conf->conf_signhdrs);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}
	else
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SIGNHDRS,
		                      (void *) should_signhdrs,
		                      sizeof (u_char **));

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	if (conf->conf_senderhdrs != NULL)
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SENDERHDRS,
		                      conf->conf_senderhdrs,
		                      sizeof conf->conf_senderhdrs);

		if (status != DKIM_STAT_OK)
			return FALSE;
	}
	else
	{
		status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
		                      DKIM_OPTS_SENDERHDRS,
		                      (void *) default_senderhdrs,
		                      sizeof (u_char **));

		if (status != DKIM_STAT_OK)
			return FALSE;
	}

	status = dkim_options(conf->conf_libopendkim, DKIM_OP_SETOPT,
	                      DKIM_OPTS_TMPDIR,
	                      (void *) conf->conf_tmpdir,
	                      sizeof conf->conf_tmpdir);

	if (status != DKIM_STAT_OK)
		return FALSE;

	if (conf->conf_thirdparty != NULL)
	{
		status = dkim_set_prescreen(conf->conf_libopendkim,
		                            dkimf_prescreen);
		if (status != DKIM_STAT_OK)
			return FALSE;
	}
	else
	{
		status = dkim_set_prescreen(conf->conf_libopendkim, NULL);
		if (status != DKIM_STAT_OK)
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
		char path[MAXPATHLEN + 1];

		strlcpy(path, conffile, sizeof path);

		cfg = config_load(conffile, dkimf_config, &line,
		                  path, sizeof path);

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
		                              sizeof errbuf) != 0)
		{
			if (curconf->conf_dolog)
				syslog(LOG_ERR, "%s: %s", conffile, errbuf);
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

			if (!dkimf_config_setlib(curconf))
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_WARNING,
					       "can't configure DKIM library; continuing");
				}
			}
		}
	}

	reload = FALSE;

	pthread_mutex_unlock(&conf_lock);

	return;
}

#ifdef _FFR_BODYLENGTH_DB
/*
**  DKIMF_CHECKBLDB -- determine if an envelope recipient is one for which
**                     signing should be done with body length tags
**
**  Parameters:
**  	to -- the recipient header
**  	jobid -- string of job ID for logging
**
**  Return value:
**  	TRUE iff the recipient email was found in the body length database.
*/

static _Bool
dkimf_checkbldb(char *to, char *jobid)
{
	_Bool exists = FALSE;
	DKIM_STAT status;
	char *domain;
	char *address;
	char addr[MAXADDRESS + 1];
	char dbaddr[MAXADDRESS + 1];

	strlcpy(addr, to, sizeof addr);
	status = rfc2822_mailbox_split(addr, &address, &domain);
	if (status != 0 || address == NULL || domain == NULL)
	{
		if (dolog)
		{
			syslog(LOG_INFO, "%s: can't parse %s: header",
			       jobid, to);
		}

		return FALSE;
	}

	if (snprintf(dbaddr, sizeof dbaddr, "%s@%s", address,
	             domain) >= (int) sizeof dbaddr)
	{
		if (dolog)
		{
			syslog(LOG_ERR, "%s overflow parsing \"%s\"",
			       jobid, to);
		}
	}

	status = dkimf_db_get(bldb, dbaddr, NULL, NULL, &exists, &bldb_lock);
	if (status == 0)
	{
		return exists;
	}
	else if (dolog)
	{
		char *err;

		err = DB_STRERROR(status);
		if (status != DB_NOTFOUND)
		{
			syslog(LOG_ERR,
			       "error looking up \"%s\" in database: %s",
			       dbaddr, err);
		}
	}

	return FALSE;
}
#endif /* _FFR_BODYLENGTH_DB */

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
dkimf_sendprogress(void *ctx)
{
	assert(ctx != NULL);

	(void) smfi_progress((SMFICTX *) ctx);
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
	ctx->mctx_dnssec_policy = DKIM_DNSSEC_UNKNOWN;
#endif /* USE_UNBOUND */

	return ctx;
}

/*
**  DKIMF_LOG_SSL_ERRORS -- log any queued SSL library errors
**
**  Parameters:
**  	jobid -- job ID to include in log messages
**  	selector -- selector to include in log messages (may be NULL)
**  	domain -- domain to use in log messsages (may be NULL)
**
**  Return value:
**  	None.
*/

static void
dkimf_log_ssl_errors(char *jobid, char *selector, char *domain)
{
	assert(jobid != NULL);

	/* log any queued SSL error messages */
	if (ERR_peek_error() != 0)
	{
		int n;
		int saveerr;
		u_long e;
		char errbuf[BUFRSZ + 1];
		char tmp[BUFRSZ + 1];

		saveerr = errno;

		memset(errbuf, '\0', sizeof errbuf);

		for (n = 0; ; n++)
		{
			e = ERR_get_error();
			if (e == 0)
				break;

			memset(tmp, '\0', sizeof tmp);
			(void) ERR_error_string_n(e, tmp, sizeof tmp);
			if (n != 0)
				strlcat(errbuf, "; ", sizeof errbuf);
			strlcat(errbuf, tmp, sizeof errbuf);
		}

		if (selector != NULL && domain != NULL)
		{
			syslog(LOG_INFO, "%s s=%s d=%s SSL %s", jobid,
			       selector, domain, errbuf);
		}
		else
		{
			syslog(LOG_INFO, "%s SSL %s", jobid, errbuf);
		}

		errno = saveerr;
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

	/* release memory */
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

#ifdef _FFR_MULTIPLE_SIGNATURES
		if (dfc->mctx_srhead != NULL)
		{
			struct signreq *sr;
			struct signreq *next;

			sr = dfc->mctx_srhead;
			while (sr != NULL)
			{
				next = sr->srq_next;

				TRYFREE(sr);

				sr = next;
			}
		}
#endif /* _FFR_MULTIPLE_SIGNATURES */

		if (dfc->mctx_dkim != NULL)
			dkim_free(dfc->mctx_dkim);
#ifdef _FFR_VBR
		if (dfc->mctx_vbr != NULL)
			vbr_close(dfc->mctx_vbr);
#endif /* _FFR_VBR */

#if VERIFY_DOMAINKEYS
		if (dfc->mctx_dk != NULL)
			dk_free(dfc->mctx_dk);
#endif /* VERIFY_DOMAINKEYS */

		if (dfc->mctx_tmpstr != NULL)
			dkimf_dstring_free(dfc->mctx_tmpstr);

		free(dfc);
		cc->cctx_msg = NULL;
	}
}

/*
**  DKIMF_LIBSTATUS -- process a final status returned from libopendkim
**
**  Parameters:
**  	ctx -- milter context
**  	where -- what function reported the error
**  	status -- status returned by a libdk call (DKIM_STAT_*)
**
**  Return value:
**   	An smfistat value to be returned to libmilter.
*/

static sfsistat
dkimf_libstatus(SMFICTX *ctx, char *where, int status)
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

	switch (status)
	{
	  case DKIM_STAT_OK:
		retcode = SMFIS_CONTINUE;
		break;

	  case DKIM_STAT_INTERNAL:
		retcode = conf->conf_handling.hndl_internal;
#ifdef _FFR_CAPTURE_UNKNOWN_ERRORS
		dfc->mctx_capture = TRUE;
#endif /* _FFR_CAPTURE_UNKNOWN_ERRORS */
		if (conf->conf_dolog)
		{
			const char *err;

			err = dkim_geterror(dfc->mctx_dkim);
			if (err == NULL)
				err = strerror(errno);

			syslog(LOG_ERR,
			       "%s: %s%sinternal error from libopendkim: %s",
			       JOBID(dfc->mctx_jobid),
			       where == NULL ? "" : where,
			       where == NULL ? "" : ": ", err);
		}
		replytxt = "internal DKIM error";
		break;

	  case DKIM_STAT_BADSIG:
		retcode = conf->conf_handling.hndl_badsig;
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: bad signature data",
			       JOBID(dfc->mctx_jobid));
		}
		replytxt = "bad DKIM signature data";

		memset(smtpprefix, '\0', sizeof smtpprefix);
		sig = dkim_getsignature(dfc->mctx_dkim);
		(void) dkim_sig_getreportinfo(dfc->mctx_dkim, sig,
		                              NULL, 0,
		                              NULL, 0,
		                              NULL, 0,
		                              NULL, 0,
		                              smtpprefix, sizeof smtpprefix,
		                              NULL);

		break;

	  case DKIM_STAT_NOSIG:
		retcode = conf->conf_handling.hndl_nosig;
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: no signature data",
			       JOBID(dfc->mctx_jobid));
		}
		replytxt = "no DKIM signature data";
		break;

	  case DKIM_STAT_NORESOURCE:
		retcode = conf->conf_handling.hndl_internal;
#ifdef _FFR_CAPTURE_UNKNOWN_ERRORS
		dfc->mctx_capture = TRUE;
#endif /* _FFR_CAPTURE_UNKNOWN_ERRORS */
		if (conf->conf_dolog)
		{
			const char *err;

			err = dkim_geterror(dfc->mctx_dkim);
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
		retcode = conf->conf_handling.hndl_badsig;
		if (conf->conf_dolog)
		{
			const char *err;

			err = dkim_geterror(dfc->mctx_dkim);
			if (err == NULL)
				err = "unknown cause";

			syslog(LOG_ERR, "%s: signature verification failed: %s",
			       JOBID(dfc->mctx_jobid), err);
		}
		replytxt = "DKIM signature verification failed";
		break;

	  case DKIM_STAT_KEYFAIL:
	  case DKIM_STAT_NOKEY:
		retcode = conf->conf_handling.hndl_dnserr;
		if (conf->conf_dolog)
		{
			const char *err;
			u_char *selector = NULL;
			u_char *domain = NULL;
			DKIM_SIGINFO *sig;

			err = dkim_geterror(dfc->mctx_dkim);

			sig = dkim_getsignature(dfc->mctx_dkim);
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
		retcode = conf->conf_handling.hndl_badsig;
		if (conf->conf_dolog)
		{
			const char *err;

			err = dkim_geterror(dfc->mctx_dkim);
			if (err == NULL)
				err = "unspecified";

			syslog(LOG_ERR, "%s: syntax error: %s",
			       JOBID(dfc->mctx_jobid), err);
		}
		replytxt = "DKIM signature syntax error";
		break;
	}

	switch (retcode)
	{
	  case SMFIS_REJECT:
		rcode = "550";
		xcode = "5.7.0";
		break;

	  case SMFIS_DISCARD:
		rcode = "451";
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
*/

static Header
dkimf_findheader(msgctx dfc, char *hname, int instance)
{
	Header hdr;

	assert(dfc != NULL);
	assert(hname != NULL);

	hdr = dfc->mctx_hqhead;

	while (hdr != NULL)
	{
		if (strcasecmp(hdr->hdr_hdr, hname) == 0)
		{
			if (instance == 0)
				return hdr;
			else
				instance--;
		}

		hdr = hdr->hdr_next;
	}

	return NULL;
}

/*
**  DKIMF_LOADKEYS -- load multiple keys
**
**  Parameters:
**  	file -- input file
**  	conf -- configuration to update
**
**  Return value:
**  	0 on success, !0 on failure
**
**  Side effects:
**  	keyhead, keytail are updated.
*/

static int
dkimf_loadkeys(char *file, struct dkimf_config *conf)
{
	_Bool blank = TRUE;
	int line = 0;
	FILE *f;
	u_char *p;
	u_char *re;
	char *domain;
	char *path;
	u_char buf[BUFRSZ + 1];
	char root[MAXPATHLEN + 1];

	assert(file != NULL);
	assert(conf != NULL);

	f = fopen(file, "r");
	if (f == NULL)
	{
		fprintf(stderr, "%s: %s: fopen(): %s\n", progname,
		        file, strerror(errno));
		return -1;
	}

	memset(root, '\0', sizeof root);
	memset(buf, '\0', sizeof buf);

	while (fgets((char *) buf, sizeof buf, f) != NULL)
	{
		/* skip comments */
		if (buf[0] == '#')
			continue;

		blank = TRUE;

		/* chomp trailing newline */
		for (p = buf; *p != '\0'; p++)
		{
			if (*p == '\n')
			{
				*p = '\0';
				break;
			}

			if (isascii(*p) && !isspace(*p))
				blank = FALSE;
		}

		/* skip blank lines */
		if (blank)
			continue;

		line++;

		if (buf[0] == '/')
		{
			strlcpy(root, (char *) buf, sizeof root);
			if (root[strlen(root) - 1] != '/')
				strlcat(root, "/", sizeof root);
		}

		re = NULL;
		domain = NULL;
		path = NULL;

		/*
		**  File format: <sender-glob>:<signing-domain>:<path-to-key>
		**
		**  This means if the sender matches <sender-glob>,
		**  sign with d=<signing-domain> and use the private
		**  key found in <path-to-key>, using the filename portion
		**  of the latter as the name of the selector.
		**
		**  <sender-glob> is string matching using "*" as a wildcard
		**  character.
		**
		**  #-delimited comments are allowed.  Blank lines are ignored.
		**
		**  A line starting with "/" is interpreted as a root directory
		**  for keys, meaning the <path-to-key> values after that
		**  in the file are taken relative to that path.
		*/

		re = (u_char *) strtok((char *) buf, ":");
		domain = strtok(NULL, ":");
		if (domain != NULL)
			path = strtok(NULL, ":");

		if (re == NULL || domain == NULL || path == NULL)
		{
			fprintf(stderr, "%s: %s: line %d: malformed\n",
			        progname, file, line);
			fclose(f);
			return -1;
		}
		else
		{
			int status;
			char *r;
			char *end;
			ssize_t n;
			struct keytable *new;
			int keyfd;
			struct stat s;
			char retmp[BUFRSZ];
			char fn[MAXPATHLEN + 1];

			dkimf_mkpath(fn, sizeof fn, root, path);
			keyfd = open(fn, O_RDONLY, 0);

			if (keyfd == -1 && errno == ENOENT)
			{
				/* try appending ".pem" */
				strlcat(fn, ".pem", sizeof fn);
				keyfd = open(fn, O_RDONLY, 0);
			}

			if (keyfd == -1 && errno == ENOENT)
			{
				/* try appending ".private" */
				dkimf_mkpath(fn, sizeof fn, root, path);
				strlcat(fn, ".private", sizeof fn);
				keyfd = open(fn, O_RDONLY, 0);
			}

			if (keyfd == -1)
			{
				dkimf_mkpath(fn, sizeof fn, root, path);
				fprintf(stderr, "%s: %s: open(): %s\n",
				        progname, fn, strerror(errno));
				fclose(f);
				return -1;
			}

			status = fstat(keyfd, &s);
			if (status == -1)
			{
				fprintf(stderr, "%s: %s: fstat(): %s\n",
				        progname, path, strerror(errno));
				close(keyfd);
				fclose(f);
				return -1;
			}

			*p = '\0';
			end = retmp + sizeof retmp - 1;
			memset(retmp, '\0', sizeof retmp);
			retmp[0] = '^';
			r = &retmp[1];

			for (p = re; *p != '\0'; p++)
			{
				switch (*p)
				{
				  case '*':
					if (r + 3 >= end)
					{
						fprintf(stderr,
						        "%s: %s: line %d: \"%s\": expression too large\n",
						        progname, file, line,
						        re);
						close(keyfd);
						fclose(f);
						return -1;
					}

					(void) strlcat(retmp, ".*",
					                  sizeof retmp);
					r += 2;
					break;

				  case '.':
				  case '$':
				  case '[':
				  case ']':
				  case '(':
				  case ')':
					if (r + 3 >= end)
					{
						fprintf(stderr,
						        "%s: %s: line %d: \"%s\": expression too large\n",
						        progname, file, line,
						        re);
						close(keyfd);
						fclose(f);
						return -1;
					}

					*r = '\\';
					r++;
					/* FALLTHROUGH */

				  default:
					*r = *p;
					r++;
					break;
				}
			}

			(void) strlcat(retmp, "$", sizeof retmp);

			new = (struct keytable *) malloc(sizeof(struct keytable));
			if (new == NULL)
			{
				fprintf(stderr, "%s: malloc(): %s\n",
				        progname, strerror(errno));
				close(keyfd);
				fclose(f);
				return -1;
			}

			new->key_next = NULL;
			r = strrchr(path, '/');
			new->key_selector = strdup(r == NULL ? path : r + 1);
			if (new->key_selector == NULL)
			{
				fprintf(stderr, "%s: strdup(): %s\n",
				        progname, strerror(errno));
				close(keyfd);
				fclose(f);
				return -1;
			}

			if (domain[0] != '*')
				new->key_domain = strdup(domain);
			else
				new->key_domain = NULL;

			status = regcomp(&new->key_re, retmp,
			                 (REG_ICASE|REG_EXTENDED));
			if (status != 0)
			{
				char err[BUFRSZ];

				memset(err, '\0', sizeof err);
				(void) regerror(status, &new->key_re,
				                err, sizeof err);
				fprintf(stderr,
				        "%s: %s: line %d: regcomp(): %s\n",
				        progname, file, line, err);
				close(keyfd);
				fclose(f);
				return -1;
			}

			new->key_data = malloc(s.st_size);
			if (new->key_data == NULL)
			{
				fprintf(stderr, "%s: malloc(): %s\n",
				        progname, strerror(errno));
				close(keyfd);
				fclose(f);
				return -1;
			}
			new->key_len = s.st_size;

			n = read(keyfd, new->key_data, s.st_size);
			if (n < s.st_size)
			{
				if (n == -1)
				{
					fprintf(stderr, "%s: %s: read(): %s\n",
					        progname, path,
					        strerror(errno));
				}
				else
				{
					fprintf(stderr,
					        "%s: %s: read() truncated\n",
					        progname, path);
				}
				close(keyfd);
				fclose(f);
				return -1;
			}

			close(keyfd);

			if (conf->conf_keyhead == NULL)
			{
				conf->conf_keyhead = new;
				conf->conf_keytail = new;
			}
			else
			{
				conf->conf_keytail->key_next = new;
				conf->conf_keytail = new;
			}
		}
	}

	fclose(f);

	return 0;
}

/*
**  DKIMF_FREEKEYS -- destroy a list of keys
**
**  Parameters:
**  	conf -- configuration handle referencing keys to be discarded
**
**  Return value:
**  	None.
*/

static void
dkimf_freekeys(struct dkimf_config *conf)
{
	struct keytable *cur;
	struct keytable *next;

	assert(conf != NULL);

	for (cur = conf->conf_keyhead; cur != NULL; cur = next)
	{
		next = cur->key_next;

		if (cur->key_selector != NULL)
			free(cur->key_selector);
		if (cur->key_domain != NULL)
			free(cur->key_domain);
		if (cur->key_data != NULL)
			free(cur->key_domain);
		regfree(&cur->key_re);

		free(cur);
	}
}

/*
**  DKIMF_SIGREPORT -- generate a report on signature failure (if possible)
**
**  Parameters:
**   	dfc -- message context
**  	conf -- current configuration object
**  	hostname -- hostname to use for reporting MTA
**
**  Return value:
**  	None.
*/

static void
dkimf_sigreport(msgctx dfc, struct dkimf_config *conf, char *hostname)
{
	_Bool sendreport = FALSE;
	int bfd = -1;
	int hfd = -1;
	int status;
#ifdef _FFR_REPORT_INTERVALS
	int icount = 0;
#endif /* _FFR_REPORT_INTERVALS */
	int arftype = ARF_TYPE_UNKNOWN;
	int arfdkim = ARF_DKIMF_UNKNOWN;
	u_int interval;
	DKIM_STAT dkstatus;
	char *p;
	char *last;
	FILE *out;
	DKIM_SIGINFO *sig;
	struct Header *hdr;
	char fmt[BUFRSZ];
	char opts[BUFRSZ];
	char addr[MAXADDRESS + 1];

	assert(dfc != NULL);
	assert(conf != NULL);
	assert(hostname != NULL);

	memset(addr, '\0', sizeof addr);
	memset(fmt, '\0', sizeof fmt);
	memset(opts, '\0', sizeof opts);

	sig = dkim_getsignature(dfc->mctx_dkim);

	/* if no report is possible, just skip it */
	dkstatus = dkim_sig_getreportinfo(dfc->mctx_dkim, sig,
	                                  &hfd, &bfd,
	                                  (u_char *) addr, sizeof addr,
	                                  (u_char *) fmt, sizeof fmt,
	                                  (u_char *) opts, sizeof opts,
	                                  NULL, 0,
	                                  &interval);
	if (dkstatus != DKIM_STAT_OK || addr[0] == '\0')
		return;

#ifdef _FFR_REPORT_INTERVALS
	if (ridb != NULL)
	{
		icount = dkimf_ridb_check(dkim_sig_getdomain(sig), interval);
		if (icount <= 0)
		{
			if (icount == -1 && conf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "%s: error checking report interval database",
				       dfc->mctx_jobid);
			}

			return;
		}
	}
#endif /* _FFR_REPORT_INTERVALS */

	/* ensure the ARF format is acceptable to the requesting domain */
	if (fmt[0] != '\0')
	{
		for (p = strtok_r(fmt, ":", &last);
		     p != NULL;
		     p = strtok_r(NULL, ":", &last))
		{
			if (strcasecmp(p, ARF_FORMAT_ARF) == 0)
				break;
		}

		if (p == NULL)
			return;
	}

	/* ignore any domain name in "r=" */
	p = strchr(addr, '@');
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
				DKIM_SIGINFO **sigs;
				int nsigs;

				(void) dkim_getsiglist(dfc->mctx_dkim,
				                       &sigs, &nsigs);
				if (nsigs == 0)
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
		}
	}

	if (!sendreport)
		return;

	pthread_mutex_lock(&popen_lock);
	out = popen(_PATH_SENDMAIL " -t" SENDMAIL_OPTIONS, "w");
	pthread_mutex_unlock(&popen_lock);

	if (out == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: popen(): %s", dfc->mctx_jobid,
			       strerror(errno));
		}

		return;
	}

	/* determine the type of ARF failure and, if needed, a DKIM fail code */
	arftype = dkimf_arftype(dfc);
	if (arftype == ARF_TYPE_DKIM)
		arfdkim = dkimf_arfdkim(dfc);

	/* From: */
	fprintf(out, "From: %s\n", reportaddr);

	/* To: */
	fprintf(out, "To: %s@%s\n", addr, dkim_sig_getdomain(sig));

	/* we presume sendmail will add Date: */

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
	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: message/feedback-report\n");
	fprintf(out, "\n");
	fprintf(out, "User-Agent: %s/%s\n", DKIMF_PRODUCTNS, DKIMF_VERSION);
	fprintf(out, "Version: %s\n", ARF_VERSION);
	fprintf(out, "Original-Envelope-Id: %s\n", dfc->mctx_jobid);
	fprintf(out, "Reporting-MTA: %s\n", hostname);
#ifdef _FFR_REPORT_INTERVALS
	if (icount > 1)
		fprintf(out, "Incidents: %d\n", icount);
#endif /* _FFR_REPORT_INTERVALS */
	fprintf(out, "Feedback-Type: %s\n", arf_type_string(arftype));
	if (arftype == ARF_TYPE_DKIM)
	{
		memset(addr, '\0', sizeof addr);
		dkim_sig_getidentity(dfc->mctx_dkim, sig, addr, sizeof addr);

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
		fprintf(out, "%s: %s\n", hdr->hdr_hdr, hdr->hdr_val);

	/* end */
	fprintf(out, "\n--dkimreport/%s/%s--\n", hostname, dfc->mctx_jobid);

	/* send it */
	pthread_mutex_lock(&popen_lock);
	status = pclose(out);
	pthread_mutex_unlock(&popen_lock);

	if (status != 0 && conf->conf_dolog)
	{
		syslog(LOG_ERR, "%s: pclose(): %s", dfc->mctx_jobid,
		       strerror(errno));
	}
}

/*
**  DKIMF_POLICYREPORT -- generate a report on policy failure (if possible)
**
**  Parameters:
**   	dfc -- message context
**  	conf -- current configuration object
**  	hostname -- hostname to use as reporting MTA
**
**  Return value:
**  	None.
*/

static void
dkimf_policyreport(msgctx dfc, struct dkimf_config *conf, char *hostname)
{
	_Bool sendreport = FALSE;
#ifdef _FFR_REPORT_INTERVALS
	int icount;
#endif /* _FFR_REPORT_INTERVALS */
	int status;
	int arftype;
	int arfdkim;
	int nsigs = 0;
	u_int interval;
	DKIM_STAT dkstatus;
	char *p;
	char *last;
	FILE *out;
	DKIM_SIGINFO **sigs;
	struct Header *hdr;
	char fmt[BUFRSZ];
	char opts[BUFRSZ];
	char addr[MAXADDRESS + 1];

	assert(dfc != NULL);
	assert(conf != NULL);
	assert(hostname != NULL);

	memset(addr, '\0', sizeof addr);
	memset(fmt, '\0', sizeof fmt);
	memset(opts, '\0', sizeof opts);

	if (dfc->mctx_dkim != NULL)
		(void) dkim_getsiglist(dfc->mctx_dkim, &sigs, &nsigs);

	/* if no report is possible, just skip it */
	dkstatus = dkim_policy_getreportinfo(dfc->mctx_dkim,
	                                     (u_char *) addr, sizeof addr,
	                                     (u_char *) fmt, sizeof fmt,
	                                     (u_char *) opts, sizeof opts,
	                                     NULL, 0,
	                                     &interval);
	if (dkstatus != DKIM_STAT_OK || addr[0] == '\0')
		return;

#ifdef _FFR_REPORT_INTERVALS
	icount = dkimf_ridb_check(dfc->mctx_domain, interval);
	if (icount <= 0)
	{
		if (icount == -1 && conf->conf_dolog)
		{
			syslog(LOG_WARNING,
			       "%s: error checking report interval database",
			       dfc->mctx_jobid);
		}

		return;
	}
#endif /* _FFR_REPORT_INTERVALS */

	/* ensure the ARF format is acceptable to the requesting domain */
	if (fmt[0] != '\0')
	{
		for (p = strtok_r(fmt, ":", &last);
		     p != NULL;
		     p = strtok_r(NULL, ":", &last))
		{
			if (strcasecmp(p, ARF_FORMAT_ARF) == 0)
				break;
		}

		if (p == NULL)
			return;
	}

	/* ignore any domain name in "r=" */
	p = strchr(addr, '@');
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
			if (strcasecmp(p, ARF_OPTIONS_ADSP_ALL) == 0)
			{
				sendreport = TRUE;
				break;
			}
			else if (strcasecmp(p, ARF_OPTIONS_ADSP_SIGNED) == 0)
			{
				if (nsigs != 0)
				{
					sendreport = TRUE;
					break;
				}
			}
			else if (strcasecmp(p, ARF_OPTIONS_ADSP_UNSIGNED) == 0)
			{
				if (nsigs == 0)
				{
					sendreport = TRUE;
					break;
				}
			}
		}
	}

	if (!sendreport)
		return;

	pthread_mutex_lock(&popen_lock);
	out = popen(_PATH_SENDMAIL " -t" SENDMAIL_OPTIONS, "w");
	pthread_mutex_unlock(&popen_lock);

	if (out == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR, "%s: popen(): %s", dfc->mctx_jobid,
			       strerror(errno));
		}

		return;
	}

	/* determine the type of ARF failure and, if needed, a DKIM fail code */
	arftype = dkimf_arftype(dfc);
	if (arftype == ARF_TYPE_DKIM)
		arfdkim = dkimf_arfdkim(dfc);

	/* we presume the MTA will add From: and Date: ... */

	/* To: */
	fprintf(out, "To: %s@%s\n", addr, dfc->mctx_domain);

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
	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: message/feedback-report\n");
	fprintf(out, "\n");
	fprintf(out, "User-Agent: %s/%s\n", DKIMF_PRODUCTNS, DKIMF_VERSION);
	fprintf(out, "Version: %s\n", ARF_VERSION);
	fprintf(out, "Original-Envelope-Id: %s\n", dfc->mctx_jobid);
	fprintf(out, "Reporting-MTA: %s\n", hostname);
#ifdef _FFR_REPORT_INTERVALS
	if (icount > 1)
		fprintf(out, "Incidents: %d\n", icount);
#endif /* _FFR_REPORT_INTERVALS */
	fprintf(out, "Feedback-Type: %s\n", arf_type_string(ARF_TYPE_FRAUD));

	fprintf(out, "\n");

	/* third part: header block */
	fprintf(out, "--dkimreport/%s/%s\n", hostname, dfc->mctx_jobid);
	fprintf(out, "Content-Type: text/rfc822-headers\n");
	fprintf(out, "\n");

	for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
		fprintf(out, "%s: %s\n", hdr->hdr_hdr, hdr->hdr_val);

	/* end */
	fprintf(out, "\n--dkimreport/%s/%s--\n", hostname, dfc->mctx_jobid);

	/* send it */
	pthread_mutex_lock(&popen_lock);
	status = pclose(out);
	pthread_mutex_unlock(&popen_lock);

	if (status != 0 && conf->conf_dolog)
	{
		syslog(LOG_ERR, "%s: pclose(): %s", dfc->mctx_jobid,
		       strerror(errno));
	}
}

#ifdef _FFR_COMMAIZE
/*
**  DKIMF_COMMAIZE_HDR -- consult list of header fields MTA would rewrite
**
**  Parameters:
**  	name -- name of header field being considered
**
**  Return value:
**  	TRUE iff the header field's name appears in the list of header
**  	fields the MTA would rewrite.
*/

static _Bool
dkimf_commaize_hdr(char *name)
{
	int c;

	assert(name != NULL);

	for (c = 0; commaize_hdrs[c] != NULL; c++)
	{
		if (strcasecmp(name, commaize_hdrs[c]) == 0)
			return TRUE;
	}

	return FALSE;
}
#endif /* _FFR_COMMAIZE */

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

static sfsistat
mlfi_negotiate(SMFICTX *ctx,
	unsigned long f0, unsigned long f1,
	unsigned long f2, unsigned long f3,
	unsigned long *pf0, unsigned long *pf1,
	unsigned long *pf2, unsigned long *pf3)
{
	unsigned long reqactions = (SMFIF_ADDHDRS |
	                            SMFIF_CHGHDRS );
	unsigned long wantactions = (SMFIF_SETSYMLIST);
	unsigned long protosteps = (SMFIP_NOHELO |
	                            SMFIP_NOUNKNOWN |
	                            SMFIP_NODATA |
	                            SMFIP_SKIP );
	connctx cc;
	struct dkimf_config *conf;

	dkimf_config_reload();

	/* initialize connection context */
	cc = malloc(sizeof(struct connctx));
	if (cc != NULL)
	{
		memset(cc, '\0', sizeof(struct connctx));

		pthread_mutex_lock(&conf_lock);

		cc->cctx_config = curconf;
		curconf->conf_refcnt++;

		conf = curconf;

		pthread_mutex_unlock(&conf_lock);

		dkimf_setpriv(ctx, cc);
	}

	/* verify the actions we need are available */
	if (quarantine)
		reqactions |= SMFIF_QUARANTINE;
# ifdef _FFR_CAPTURE_UNKNOWN_ERRORS
	reqactions |= SMFIF_QUARANTINE;
# endif /* _FFR_CAPTURE_UNKNOWN_ERRORS */
	if ((f0 & reqactions) != reqactions)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_ERR,
			       "mlfi_negotiate(): required milter action(s) not available (got 0x%lx, need 0x%lx)",
			       f0, reqactions);
		}

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

				return SMFIS_REJECT;
			}
		}

		if (smfi_setsymlist(ctx, SMFIM_EOH, macrolist) != MI_SUCCESS)
		{
			if (conf->conf_dolog)
				syslog(LOG_ERR, "smfi_setsymlist() failed");

			return SMFIS_REJECT;
		}
	}

	/* set "milterv2" flag if SMFIP_SKIP was available */
	if ((f1 & SMFIP_SKIP) != 0)
		cc->cctx_milterv2 = TRUE;

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
	connctx cc;
	struct dkimf_config *conf;

	dkimf_config_reload();

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
	if (conf->conf_peerlist != NULL)
	{
		/* try hostname, if available */
		if (host != NULL && host[0] != '\0' && host[0] != '[')
		{
			dkimf_lowercase((u_char *) host);
			if (dkimf_checkhost(conf->conf_peerlist, host))
				return SMFIS_ACCEPT;
		}

		/* try IP address, if available */
		if (ip != NULL && ip->sa_family == AF_INET)
		{
			if (dkimf_checkip(conf->conf_peerlist, ip))
				return SMFIS_ACCEPT;
		}
	}

	strlcpy(cc->cctx_host, host, sizeof cc->cctx_host);

	if (ip == NULL)
	{
		struct sockaddr_in sin;

		memset(&sin, '\0', sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		memcpy(&cc->cctx_ip, &sin, sizeof(cc->cctx_ip));
	}
	else
	{
		memcpy(&cc->cctx_ip, ip, sizeof(cc->cctx_ip));
	}

	cc->cctx_msg = NULL;

	return SMFIS_CONTINUE;
}

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
	struct addrlist *a;
	char addr[MAXADDRESS + 1];

	assert(ctx != NULL);
	assert(envrcpt != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

#ifdef _FFR_BODYLENGTH_DB
	if (conf->conf_dontsignto != NULL || bldb != NULL)
#else /* _FFR_BODYLENGTH_DB */
	if (conf->conf_dontsignto != NULL)
#endif /* _FFR_BODYLENGTH_DB */
	{
		strlcpy(addr, envrcpt[0], sizeof addr);
		dkimf_stripbrackets(addr);
	}

	if (conf->conf_dontsignto != NULL)
	{
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

#ifdef _FFR_BODYLENGTH_DB
	if (bldb != NULL && dkimf_checkbldb(addr, dfc->mctx_jobid))
	{
		dfc->mctx_ltag = TRUE;
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
				"%s matched %s, signing with l= requested",
				dfc->mctx_jobid, addr);
		}
	}
#endif /*  _FFR_BODYLENGTH_DB */

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

		return conf->conf_handling.hndl_security;
	}

	newhdr = (Header) malloc(sizeof(struct Header));
	if (newhdr == NULL)
	{
		if (conf->conf_dolog)
			syslog(LOG_ERR, "malloc(): %s", strerror(errno));

		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

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
		if (isascii(*p) && isspace(*p))
			p++;

#ifdef _FFR_COMMAIZE
		if (conf->conf_commaize && dkimf_commaize_hdr(headerf))
		{
			dkimf_commaize(dfc->mctx_tmpstr, p,
			               strlen(headerf) + 2, MTAMARGIN,
			               cc->cctx_noleadspc);
		}
		else
		{
			dkimf_dstring_copy(dfc->mctx_tmpstr, p);
		}
#else /* _FFR_COMMAIZE */
		dkimf_dstring_copy(dfc->mctx_tmpstr, p);
#endif /* _FFR_COMMAIZE */
	}
	else
	{
#ifdef _FFR_COMMAIZE
		if (conf->conf_commaize && dkimf_commaize_hdr(headerf))
		{
			dkimf_commaize(dfc->mctx_tmpstr, headerv,
			               strlen(headerf) + 1, MTAMARGIN,
			               cc->cctx_noleadspc);
		}
		else
		{
			dkimf_dstring_copy(dfc->mctx_tmpstr, headerv);
		}
#else /* _FFR_COMMAIZE */
		dkimf_dstring_copy(dfc->mctx_tmpstr, headerv);
#endif /* _FFR_COMMAIZE */
	}

#ifdef _FFR_REPLACE_RULES
	if (conf->conf_replist != NULL)	/* XXX -- signing mode only? */
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

	newhdr->hdr_val = strdup(dkimf_dstring_get(dfc->mctx_tmpstr));

	newhdr->hdr_next = NULL;

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

#if _FFR_SELECT_CANONICALIZATION
	if (strcasecmp(headerf, XSELECTCANONHDR) == 0)
	{
		int c;
		char *slash;

		slash = strchr(headerv, '/');
		if (slash != NULL)
		{
			*slash = '\0';

			c = dkimf_configlookup(headerv, dkimf_canon);
			if (c != -1)
				dfc->mctx_hdrcanon = (dkim_canon_t) c;
			c = dkimf_configlookup(slash + 1, dkimf_canon);
			if (c != -1)
				dfc->mctx_bodycanon = (dkim_canon_t) c;

			*slash = '/';
		}
		else
		{
			c = dkimf_configlookup(headerv, dkimf_canon);
			if (c != -1)
				dfc->mctx_hdrcanon = (dkim_canon_t) c;
		}

		/* XXX -- eat this header? */
	}
#endif /* _FFR_SELECT_CANONICALIZATION */

#if VERIFY_DOMAINKEYS
	if (strcasecmp(headerf, DK_SIGNHEADER) == 0)
		dfc->mctx_dksigned = TRUE;
#endif /* VERIFY_DOMAINKEYS */

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
	int c;
	DKIM_STAT status;
	sfsistat ms = SMFIS_CONTINUE;
	connctx cc;
	msgctx dfc;
	char *p;
	char *user;
	char *domain;
#ifdef _FFR_VBR
	char *vbr_cert = NULL;
	char *vbr_type = NULL;
#endif /* _FFR_VBR */
	struct dkimf_config *conf;
	Header from = NULL;
	Header hdr;
	char addr[MAXADDRESS + 1];

	assert(ctx != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	dfc = cc->cctx_msg;
	assert(dfc != NULL);
	conf = cc->cctx_config;

	/*
	**  Determine the message ID for logging.
	*/

	dfc->mctx_jobid = dkimf_getsymval(ctx, "i");
	if (dfc->mctx_jobid == NULL)
		dfc->mctx_jobid = JOBIDUNKNOWN;

	/* find the Sender: or From: header */
	memset(addr, '\0', sizeof addr);

	for (c = 0; conf->conf_senderhdrs[c] != NULL; c++)
	{
		if (strcasecmp("from", conf->conf_senderhdrs[c]) == 0)
			didfrom = TRUE;

		from = dkimf_findheader(dfc, conf->conf_senderhdrs[c], 0);
		if (from != NULL)
			break;
	}

	if (from == NULL && !didfrom)
		from = dkimf_findheader(dfc, "from", 0);

	if (from == NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "%s: no sender header found; accepting",
			       dfc->mctx_jobid);
		}

		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
		return SMFIS_CONTINUE;
	}

	/* extract the sender's domain */
	strlcpy(addr, from->hdr_val, sizeof addr);
	status = rfc2822_mailbox_split(addr, &user, &domain);
	if (status != 0 || user == NULL || domain == NULL ||
	    user[0] == '\0' || domain[0] == '\0')
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_INFO,
			       "%s: can't parse %s: header value `%s'",
			       dfc->mctx_jobid, from->hdr_hdr, from->hdr_val);
		}

		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
		return SMFIS_CONTINUE;
	}
	strlcpy(dfc->mctx_domain, domain, sizeof dfc->mctx_domain);

	/* assume we're not signing */
	dfc->mctx_signalg = DKIM_SIGN_UNKNOWN;
	dfc->mctx_signing = FALSE;
	domainok = FALSE;
	originok = FALSE;

	/* is it a domain we sign for? */
	if (conf->conf_domains != NULL)
	{
		int n;

		if (conf->conf_dompats != NULL)
		{
			for (n = 0; conf->conf_dompats[n] != NULL; n++)
			{
				status = regexec(conf->conf_dompats[n],
				                 dfc->mctx_domain,
				                 0, NULL, 0);
				if (status == 0)
				{
					domainok = TRUE;
					break;
				}
			}
		}
		else
		{
			for (n = 0; conf->conf_domains[n] != NULL; n++)
			{
				if (strcasecmp(dfc->mctx_domain,
				               conf->conf_domains[n]) == 0)
				{
					strlcpy(dfc->mctx_domain,
					           conf->conf_domains[n],
					           sizeof dfc->mctx_domain);

					domainok = TRUE;
					break;
				}
			}
		}

		if (!domainok && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s no signing domain match for `%s'",
			       dfc->mctx_jobid, dfc->mctx_domain);
		}

		if (conf->conf_subdomains && !domainok)
		{
			for (p = strchr(dfc->mctx_domain, '.');
			     p != NULL && !domainok;
			     p = strchr(p, '.'))
			{
				p++;
				if (*p == '\0')
					break;

				if (conf->conf_dompats != NULL)
				{
					for (n = 0;
					     conf->conf_dompats[n] != NULL;
					     n++)
					{
						status = regexec(conf->conf_dompats[n],
						                 dfc->mctx_domain,
						                 0, NULL, 0);
						if (status == 0)
						{
							domainok = TRUE;
							break;
						}
					}
				}
				else
				{
					for (n = 0;
					     conf->conf_domains[n] != NULL;
					     n++)
					{
						if (strcasecmp(p,
						               conf->conf_domains[n]) == 0)
						{
							strlcpy(dfc->mctx_domain,
							           conf->conf_domains[n],
							           sizeof dfc->mctx_domain);
							domainok = TRUE;
							break;
						}
					}
				}
			}
			
			if (domainok)
				setidentity = TRUE;
		}

		if (!domainok && conf->conf_logwhy)
		{
			syslog(LOG_INFO,
			       "%s no signing subdomain match for `%s'",
			       dfc->mctx_jobid, dfc->mctx_domain);
		}
	}

#ifdef _FFR_SELECTOR_HEADER
	/* was there a header naming the selector to use? */
	if (domainok && conf->conf_selectorhdr != NULL)
	{
		/* find the header */
		hdr = dkimf_findheader(dfc, conf->conf_selectorhdr, 0);

		/* did it match a selector in the keylist? */
		if (hdr != NULL)
		{
			struct keytable *curkey;

			for (curkey = conf->conf_keyhead;
			     curkey != NULL;
			     curkey = curkey->key_next)
			{
				if (strcasecmp(curkey->key_selector,
				               hdr->hdr_val) == 0)
				{
					dfc->mctx_key = curkey;
					break;
				}
			}
		}
	}
#endif /* _FFR_SELECTOR_HEADER */

	/* still no key selected; check the keylist (if any) */
	if (dfc->mctx_key == NULL && conf->conf_keyhead != NULL)
	{
		struct keytable *curkey;
		char srchaddr[MAXADDRESS + 1];

		snprintf(srchaddr, sizeof srchaddr, "%s@%s",
		         user, dfc->mctx_domain);

		/* select the key */
		for (curkey = conf->conf_keyhead;
		     curkey != NULL;
		     curkey = curkey->key_next)
		{
			status = regexec(&curkey->key_re, srchaddr,
			                 0, NULL, 0);
			if (status == 0)
#ifdef _FFR_MULTIPLE_SIGNATURES
			{
				if (conf->conf_multisig)
				{
					dkimf_add_signrequest(dfc, curkey);
					domainok = TRUE;

					if (conf->conf_subdomains &&
					    dkimf_subdomain(dfc->mctx_domain,
					                    curkey->key_domain))
						setidentity = TRUE;

					continue;
				}
				else
				{
					break;
				}
			}
#else /* _FFR_MULTIPLE_SIGNATURES */
				break;
#endif /* _FFR_MULTIPLE_SIGNATURES */

			if (status != REG_NOMATCH)
			{
				if (conf->conf_dolog)
				{
					char err[BUFRSZ];

					(void) regerror(status,
					                &curkey->key_re,
					                err, sizeof err);
					syslog(LOG_ERR,
					       "%s regexec(): %s",
					       dfc->mctx_jobid, err);
				}

				dkimf_cleanup(ctx);
				return SMFIS_TEMPFAIL;
			}
		}

#ifdef _FFR_MULTIPLE_SIGNATURES
		if (curkey != NULL && !conf->conf_multisig)
#else /* _FFR_MULTIPLE_SIGNATURES */
		if (curkey != NULL)
#endif /* ! _FFR_MULTIPLE_SIGNATURES */
		{
			if (conf->conf_subdomains &&
			    dkimf_subdomain(dfc->mctx_domain,
			                    curkey->key_domain))
				setidentity = TRUE;

			dfc->mctx_key = curkey;
			domainok = TRUE;
		}
	}

	if (!domainok && conf->conf_logwhy)
	{
		syslog(LOG_INFO, "%s no signing keylist match for `%s@%s'",
		       dfc->mctx_jobid, user, dfc->mctx_domain);
	}

	/* see if it came in on an authorized MSA/MTA connection */
	if (conf->conf_mtas != NULL)
	{
		int n;
		char *mtaname;

		mtaname = dkimf_getsymval(ctx, "{daemon_name}");

		if (mtaname != NULL)
		{
			for (n = 0; conf->conf_mtas[n] != NULL; n++)
			{
				if (strcasecmp(mtaname,
				               conf->conf_mtas[n]) == 0)
				{
					originok = TRUE;
					break;
				}
			}
		}

		if (!originok && conf->conf_logwhy)
		{
			syslog(LOG_INFO, "%s no MTA name match",
			       dfc->mctx_jobid);
		}
	}

	/* see if macro tests passed */
	if (conf->conf_macros != NULL)
	{
		_Bool done = FALSE;
		int n;
		char *val;
		char *vals;
		char *last;
		char name[BUFRSZ + 1];

		if (dfc->mctx_tmpstr == NULL)
		{
			dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);
			if (dfc->mctx_tmpstr == NULL)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s dkimf_dstring_new() failed",
					       dfc->mctx_jobid);
				}

				dkimf_cleanup(ctx);
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

			/* macro set and we don't care about the value */
			if (val != NULL && conf->conf_values[n] == NULL)
			{
				originok = TRUE;
				break;
			}

			dkimf_dstring_blank(dfc->mctx_tmpstr);
			dkimf_dstring_copy(dfc->mctx_tmpstr,
			                   conf->conf_values[n]);
			vals = dkimf_dstring_get(dfc->mctx_tmpstr);

			for (p = strtok_r(vals, "|", &last);
			     !done && p != NULL;
			     p = strtok_r(NULL, "|", &last))
			{
				if (strcasecmp(val, p) == 0)
				{
					originok = TRUE;
					done = TRUE;
				}
			}
		}

		if (!originok && conf->conf_logwhy)
		{
			syslog(LOG_INFO, "%s no macros match",
			       dfc->mctx_jobid);
		}
	}

	/* see if it came from an internal or authenticated source */
	if (!originok)
	{
		_Bool internal;
#if POPAUTH
		_Bool popauth;
#endif /* POPAUTH */
		char *authtype;

		internal = dkimf_checkhost(conf->conf_internal, cc->cctx_host);
		internal = internal || dkimf_checkip(conf->conf_internal,
		                                     &cc->cctx_ip);

		authtype = dkimf_getsymval(ctx, "{auth_type}");

#if POPAUTH
		popauth = dkimf_checkpopauth(popdb, &cc->cctx_ip);
#endif /* POPAUTH */

		if ((authtype == NULL || authtype[0] == '\0') &&
#if POPAUTH
		    !popauth &&
#endif /* POPAUTH */
		    !internal)
		{
			if (domainok && conf->conf_dolog &&
			    !dkimf_checkhost(conf->conf_exignore,
			                     cc->cctx_host) &&
			    !dkimf_checkip(conf->conf_exignore, &cc->cctx_ip))
			{
				syslog(LOG_NOTICE,
				       "%s external host %s attempted to send as %s",
				       dfc->mctx_jobid, cc->cctx_host,
				       dfc->mctx_domain);
			}
		}
		else
		{
			originok = TRUE;
		}

		if (!originok && conf->conf_logwhy)
		{
			if (!internal)
			{
				syslog(LOG_INFO, "%s not internal",
				       dfc->mctx_jobid);
			}

			if (authtype == NULL || authtype[0] == '\0')
			{
				syslog(LOG_INFO, "%s not authenticated",
				       dfc->mctx_jobid);
			}

#if POPAUTH
			if (!popauth)
			{
				syslog(LOG_INFO, "%s not POP authenticated",
				       dfc->mctx_jobid);
			}
#endif /* POPAUTH */
		}
	}

	/* set signing mode if the tests passed */
	if (domainok && originok)
	{
		dfc->mctx_signalg = conf->conf_signalg;
		dfc->mctx_signing = TRUE;
		dfc->mctx_addheader = TRUE;
	}

	if (conf->conf_logwhy)
	{
		syslog(LOG_INFO, "%s mode select: %s", dfc->mctx_jobid,
		       dfc->mctx_signing ? "signing" : "verifying");
	}

	/*
	**  If we're not operating in the role matching the required operation,
	**  just accept the message and be done with it.
	*/

	if ((dfc->mctx_signing &&
	     (conf->conf_mode & DKIMF_MODE_SIGNER) == 0) ||
	    (!dfc->mctx_signing &&
	     (conf->conf_mode & DKIMF_MODE_VERIFIER) == 0))
		return SMFIS_ACCEPT;

	/* confirm that we've got a key for signing when a keylist is in use */
	if (dfc->mctx_signing && dfc->mctx_key == NULL &&
#ifdef _FFR_MULTIPLE_SIGNATURES
	    dfc->mctx_srhead == NULL &&
#endif /* _FFR_MULTIPLE_SIGNATURES */
	    conf->conf_keyhead != NULL)
	{
		if (conf->conf_dolog)
		{
			syslog(LOG_NOTICE, "%s no key selected for signing",
			       dfc->mctx_jobid);
		}

		return SMFIS_TEMPFAIL;
	}

	/* check for "DontSignMailTo" */
	if (dfc->mctx_signing && conf->conf_dontsignto != NULL)
	{
		int status;
		struct addrlist *a;

		a = dfc->mctx_rcptlist;

		while (a != NULL)
		{
			for (c = 0; conf->conf_dontsignto[c] != NULL; c++)
			{
				if (conf->conf_nosignpats != NULL)
				{
					status = regexec(conf->conf_nosignpats[c],
					                 a->a_addr, 0, NULL, 0);
					if (status == 0)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_INFO,
							       "%s skipping signing of mail to `%s'",
							       dfc->mctx_jobid,
							       a->a_addr);
						}

						return SMFIS_ACCEPT;
					}
					else if (status != REG_NOMATCH)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_ERR,
							       "%s regexec() failed",
							       dfc->mctx_jobid);
						}

						return SMFIS_TEMPFAIL;
					}
				}
				else if (strcasecmp(a->a_addr,
				                    conf->conf_dontsignto[c]) == 0)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_INFO,
						       "%s skipping signing of mail to `%s'",
						       dfc->mctx_jobid,
						       a->a_addr);
					}

					return SMFIS_ACCEPT;
				}
			}

			a = a->a_next;
		}
	}

	/* grab an appropriate handle for message processing */
	if (!dfc->mctx_signing)
	{
		dfc->mctx_dkim = dkim_verify(conf->conf_libopendkim,
		                             dfc->mctx_jobid, NULL,
		                             &status);
	}
#ifdef _FFR_MULTIPLE_SIGNATURES
	else if (dfc->mctx_srhead != NULL)
	{
		char *sdomain;
		struct signreq *sr;

		for (sr = dfc->mctx_srhead; sr != NULL; sr = sr->srq_next)
		{
			if (sr->srq_key->key_domain != NULL)
				sdomain = sr->srq_key->key_domain;
			else
				sdomain = dfc->mctx_domain;

			sr->srq_dkim = dkim_sign(conf->conf_libopendkim,
			                         dfc->mctx_jobid, NULL,
			                         (dkim_sigkey_t) sr->srq_key->key_data,
			                         sr->srq_key->key_selector,
			                         sdomain,
			                         dfc->mctx_hdrcanon,
			                         dfc->mctx_bodycanon,
			                         dfc->mctx_signalg,
			                         conf->conf_signbytes,
			                         &status);

			if (setidentity &&
			    dkimf_subdomain(dfc->mctx_domain, sdomain))
			{
				char identity[MAXADDRESS + 1];

				snprintf(identity, sizeof identity, "@%s",
				         dfc->mctx_domain);

				dkim_set_signer(sr->srq_dkim, identity);
			}

			if (sr->srq_dkim == NULL && status != DKIM_STAT_OK)
			{
				return dkimf_libstatus(ctx, "dkim_new()",
				                       status);
			}

			(void) dkim_set_user_context(sr->srq_dkim, ctx);
		}
	}
#endif /* _FFR_MULTIPLE_SIGNATURES */
	else if (dfc->mctx_key != NULL)
	{
		char *sdomain;

		if (dfc->mctx_key->key_domain != NULL)
			sdomain = dfc->mctx_key->key_domain;
		else
			sdomain = dfc->mctx_domain;

		dfc->mctx_dkim = dkim_sign(conf->conf_libopendkim,
		                           dfc->mctx_jobid, NULL,
		                           (dkim_sigkey_t) dfc->mctx_key->key_data,
		                           dfc->mctx_key->key_selector,
		                           sdomain,
		                           dfc->mctx_hdrcanon,
		                           dfc->mctx_bodycanon,
		                           dfc->mctx_signalg,
		                           conf->conf_signbytes, &status);
	}
	else
	{
		dfc->mctx_dkim = dkim_sign(conf->conf_libopendkim,
		                           dfc->mctx_jobid, NULL,
		                           conf->conf_seckey,
		                           conf->conf_selector,
		                           dfc->mctx_domain,
		                           dfc->mctx_hdrcanon,
		                           dfc->mctx_bodycanon,
		                           dfc->mctx_signalg,
		                           conf->conf_signbytes, &status);
	}

	if (dfc->mctx_dkim == NULL && status != DKIM_STAT_OK)
		return dkimf_libstatus(ctx, "dkim_new()", status);

#ifdef _FFR_MULTIPLE_SIGNATURES
	if (dfc->mctx_dkim != NULL)
#endif /* _FFR_MULTIPLE_SIGNATURES */
	(void) dkim_set_user_context(dfc->mctx_dkim, ctx);

	/* if requested, verify RFC2822-required headers (RFC2822 3.6) */
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
				       "%s RFC2822 header requirement error",
				       dfc->mctx_jobid);
			}

			dfc->mctx_addheader = TRUE;
			dfc->mctx_headeronly = TRUE;
			dfc->mctx_status = DKIMF_STATUS_BADFORMAT;
			return SMFIS_CONTINUE;
		}
	}

#ifdef _FFR_MULTIPLE_SIGNATURES
	if (dfc->mctx_signing && setidentity && !conf->conf_multisig)
#else /* _FFR_MULTIPLE_SIGNATURES */
	if (dfc->mctx_signing && setidentity)
#endif /* _FFR_MULTIPLE_SIGNATURES */
	{
		char identity[MAXADDRESS + 1];

		snprintf(identity, sizeof identity, "@%s", dfc->mctx_domain);

		dkim_set_signer(dfc->mctx_dkim, identity);
	}

#if _FFR_BODYLENGTH_DB
	if (dfc->mctx_ltag && dfc->mctx_signing)
		dkim_setpartial(dfc->mctx_dkim, TRUE);
#endif /* _FFR_BODYLENGTH_DB */

#if _FFR_VBR
	/* establish a VBR handle */
	dfc->mctx_vbr = vbr_init(NULL, NULL, NULL);
	if (dfc->mctx_vbr == NULL)
	{
		syslog(LOG_ERR, "%s can't create VBR context",
		       dfc->mctx_jobid);
		dkimf_cleanup(ctx);
		return SMFIS_TEMPFAIL;
	}

	/* store trusted certifiers */
	if (conf->conf_vbr_trusted != NULL)
		vbr_trustedcerts(dfc->mctx_vbr, conf->conf_vbr_trusted);

	/* if signing, store the values needed to make a header */
	if (dfc->mctx_signing)
	{
		/* set the sending domain */
		vbr_setdomain(dfc->mctx_vbr, dfc->mctx_domain);

		/* VBR-Type; get value from headers or use default */
		hdr = dkimf_findheader(dfc, XVBRTYPEHEADER, 0);
		if (hdr != NULL)
			vbr_type = hdr->hdr_val;
		else
			vbr_type = conf->conf_vbr_deftype;

		/* X-VBR-Certifiers; get value from headers or use default */
		hdr = dkimf_findheader(dfc, XVBRCERTHEADER, 0);
		if (hdr != NULL)
			vbr_cert = hdr->hdr_val;
		else
			vbr_cert = conf->conf_vbr_defcert;

		/* set the message type and certifiers */
		if (vbr_type != NULL && vbr_cert != NULL)
		{
			/* set the VBR transaction type */
			(void) vbr_settype(dfc->mctx_vbr, vbr_type);
	
			/* set the VBR certifier list */
			(void) vbr_setcert(dfc->mctx_vbr, vbr_cert);
		}
	}
#endif /* _FFR_VBR */

#if VERIFY_DOMAINKEYS
	if (dfc->mctx_dksigned && !dfc->mctx_signing)
	{
		dfc->mctx_dk = dk_verify(libdk, dfc->mctx_jobid, NULL,
		                         &status);
		if (dfc->mctx_dk == NULL && status != DKIM_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: dk_verify() returned status %d",
				       dfc->mctx_jobid, status);
			}

			/* XXX -- temp-fail or continue? */
		}
	}
#endif /* VERIFY_DOMAINKEYS */

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

		dkimf_dstring_copy(dfc->mctx_tmpstr, hdr->hdr_hdr);
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

#ifdef _FFR_MULTIPLE_SIGNATURES
		if (dfc->mctx_signing && dfc->mctx_srhead != NULL)
		{
			status = dkimf_msr_header(dfc->mctx_srhead,
				                  dkimf_dstring_get(dfc->mctx_tmpstr),
				                  dkimf_dstring_len(dfc->mctx_tmpstr));
			if (status != DKIM_STAT_OK)
			{
				ms = dkimf_libstatus(ctx, "dkim_header()",
				                     status);
				break;
			}
		}
		else
		{
#endif /* _FFR_MULTIPLE_SIGNATURES */
		status = dkim_header(dfc->mctx_dkim,
		                     (u_char *) dkimf_dstring_get(dfc->mctx_tmpstr),
		                     dkimf_dstring_len(dfc->mctx_tmpstr));

		if (status != DKIM_STAT_OK)
			ms = dkimf_libstatus(ctx, "dkim_header()", status);
#ifdef _FFR_MULTIPLE_SIGNATURES
		}
#endif /* _FFR_MULTIPLE_SIGNATURES */

#if VERIFY_DOMAINKEYS
		if (dfc->mctx_dk != NULL)
		{
			dkimf_dstring_cat(dfc->mctx_tmpstr, CRLF);
			status = dk_header(dfc->mctx_dk,
			                   dkimf_dstring_get(dfc->mctx_tmpstr),
			                   dkimf_dstring_len(dfc->mctx_tmpstr));
			if (status != DK_STAT_OK)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s: dk_header() returned status %d",
					       dfc->mctx_jobid, status);
				}

				dk_free(dfc->mctx_dk);
				dfc->mctx_dk = NULL;
			}
		}
#endif /* VERIFY_DOMAINKEYS */
	}

#if VERIFY_DOMAINKEYS
	/* signal end of headers to libdk */
	if (dfc->mctx_dk != NULL)
	{
		status = dk_eoh(dfc->mctx_dk);
		if (status != DK_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: dk_eoh() returned status %d",
				       dfc->mctx_jobid, status);
			}

			dk_free(dfc->mctx_dk);
			dfc->mctx_dk = NULL;
		}
	}
#endif /* VERIFY_DOMAINKEYS */

	/* return any error status from earlier */
	if (ms != SMFIS_CONTINUE)
		return ms;

	/* signal end of headers to libopendkim */
#ifdef _FFR_MULTIPLE_SIGNATURES
	if (dfc->mctx_signing && dfc->mctx_srhead != NULL)
	{
		status = dkimf_msr_eoh(dfc->mctx_srhead);
	}
	else
	{
#endif /* _FFR_MULTIPLE_SIGNATURES */
	status = dkim_eoh(dfc->mctx_dkim);
#ifdef _FFR_MULTIPLE_SIGNATURES
	}
#endif /* _FFR_MULTIPLE_SIGNATURES */
	switch (status)
	{
	  case DKIM_STAT_REVOKED:
		dfc->mctx_status = DKIMF_STATUS_REVOKED;
		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_BADSIG:
		dfc->mctx_status = DKIMF_STATUS_BAD;
		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		return SMFIS_CONTINUE;

	  case DKIM_STAT_NOSIG:
		dfc->mctx_status = DKIMF_STATUS_NOSIGNATURE;
		if (conf->conf_alwaysaddar)
		{
			dfc->mctx_addheader = TRUE;
			dfc->mctx_headeronly = TRUE;
		}
		return SMFIS_CONTINUE;

	  case DKIM_STAT_NOKEY:
		dfc->mctx_status = DKIMF_STATUS_NOKEY;
		dfc->mctx_addheader = TRUE;
		dfc->mctx_headeronly = TRUE;
		return SMFIS_CONTINUE;

	  /* XXX -- other codes? */

	  case DKIM_STAT_OK:
		return SMFIS_CONTINUE;

	  default:
		return dkimf_libstatus(ctx, "dkim_eoh()", status);
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
	msgctx dfc;
	connctx cc;
	struct dkimf_config *conf;

	assert(ctx != NULL);
	assert(bodyp != NULL);

	cc = (connctx) dkimf_getpriv(ctx);
	assert(cc != NULL);
	conf = cc->cctx_config;
	dfc = cc->cctx_msg;
	assert(dfc != NULL);

#if VERIFY_DOMAINKEYS
	if (dfc->mctx_dk != NULL)
	{
		status = dk_body(dfc->mctx_dk, bodyp, bodylen);
		if (status != DK_STAT_OK)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR,
				       "%s: dk_body() returned status %d",
				       dfc->mctx_jobid, status);
			}

			dk_free(dfc->mctx_dk);
			dfc->mctx_dk = NULL;
		}
	}
#endif /* VERIFY_DOMAINKEYS */

	/*
	**  No need to do anything if the body was empty.
	*/

	if (bodylen == 0 || dfc->mctx_headeronly)
		return SMFIS_CONTINUE;

#ifdef _FFR_MULTIPLE_SIGNATURES
	if (dfc->mctx_signing && dfc->mctx_srhead != NULL)
	{
		status = dkimf_msr_body(dfc->mctx_srhead, bodyp, bodylen);
	}
	else
	{
#endif /* _FFR_MULTIPLE_SIGNATURES */
	status = dkim_body(dfc->mctx_dkim, bodyp, bodylen);
#ifdef _FFR_MULTIPLE_SIGNATURES
	}
#endif /* _FFR_MULTIPLE_SIGNATURES */
	if (status != DKIM_STAT_OK)
		return dkimf_libstatus(ctx, "dkim_body()", status);

#ifdef SMFIS_SKIP
# ifdef _FFR_MULTIPLE_SIGNATURES
	if (dfc->mctx_signing && dfc->mctx_srhead != NULL && cc->cctx_milterv2)
	{
		if (dkimf_msr_minbody(dfc->mctx_srhead) == 0)
			return SMFIS_SKIP;
	}
	else
	{
# endif /* _FFR_MULTIPLE_SIGNATURES */
	if (cc->cctx_milterv2 && dkim_minbody(dfc->mctx_dkim) == 0)
		return SMFIS_SKIP;
# ifdef _FFR_MULTIPLE_SIGNATURES
	}
# endif /* _FFR_MULTIPLE_SIGNATURES */
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
	int status = DKIM_STAT_OK;
	dkim_policy_t pcode = DKIM_POLICY_NONE;
	int presult = DKIM_PRESULT_NONE;
	int c;
	sfsistat ret;
	connctx cc;
	msgctx dfc;
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

	/*
	**  If necessary, try again to get the job ID in case it came down
	**  later than expected (e.g. postfix).
	*/

	if (dfc->mctx_jobid == JOBIDUNKNOWN)
	{
		dfc->mctx_jobid = dkimf_getsymval(ctx, "i");
		if (dfc->mctx_jobid == NULL)
		{
			if (no_i_whine && conf->conf_dolog)
			{
				syslog(LOG_WARNING,
				       "WARNING: sendmail symbol 'i' not available");
				no_i_whine = FALSE;
			}
			dfc->mctx_jobid = JOBIDUNKNOWN;
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

	/* remove old signatures when signing */
	if (conf->conf_remsigs && dfc->mctx_signing)
	{
		for (hdr = dfc->mctx_hqhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (strcasecmp(hdr->hdr_hdr, DKIM_SIGNHEADER) == 0)
			{
				if (smfi_chgheader(ctx, hdr->hdr_hdr,
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

	/* log something if the message was multiply signed */
	if (!dfc->mctx_signing && dfc->mctx_dkim != NULL && conf->conf_dolog)
	{
		int nsigs;
		DKIM_SIGINFO **sigs;

		status = dkim_getsiglist(dfc->mctx_dkim, &sigs, &nsigs);
		if (status == DKIM_STAT_OK && nsigs > 1)
		{
			if (dfc->mctx_tmpstr == NULL)
			{
				dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);

				if (dfc->mctx_tmpstr == NULL)
				{
					syslog(LOG_WARNING,
					       "%s dkimf_dstring_new() failed",
					       dfc->mctx_jobid);

					return SMFIS_TEMPFAIL;
				}
			}
			else
			{
				dkimf_dstring_blank(dfc->mctx_tmpstr);
			}

			dkimf_dstring_cat(dfc->mctx_tmpstr,
			                  "message has signatures from ");

			for (c = 0; c < nsigs; c++)
			{
				if (c != 0)
				{
					dkimf_dstring_cat(dfc->mctx_tmpstr,
					                  ", ");
				}

				dkimf_dstring_cat(dfc->mctx_tmpstr,
				                  (char *) dkim_sig_getdomain(sigs[c]));
			}

			syslog(LOG_INFO, "%s",
			       dkimf_dstring_get(dfc->mctx_tmpstr));
		}
	}

	/*
	**  Remove all Authentication-Results: headers as per configuration
	**  options when verifying.
	*/

	if (!dfc->mctx_signing)
	{
		struct authres *ares;

		ares = (struct authres *) malloc(sizeof(struct authres));
		if (ares == NULL)
		{
			syslog(LOG_WARNING,
			       "%s malloc(): %s", dfc->mctx_jobid,
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
						       "%s failed to parse %s: header",
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
					
				if (conf->conf_remar != NULL)
				{
					if (dkimf_hostlist((char *) ares->ares_host,
					                   conf->conf_remar))
						hostmatch = TRUE;
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
					if (smfi_chgheader(ctx, hdr->hdr_hdr,
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

#ifdef _FFR_MULTIPLE_SIGNATURES
	if (!dfc->mctx_headeronly &&
	    (dfc->mctx_dkim != NULL || dfc->mctx_srhead != NULL))
#else /* _FFR_MULTIPLE_SIGNATURES */
	if (!dfc->mctx_headeronly && dfc->mctx_dkim != NULL)
#endif /* _FFR_MULTIPLE_SIGNATURES */
	{
		/* XXX -- (void) dkim_set_user_context(dfc->mctx_dkim, ctx); */

		/*
		**  Signal end-of-message to DKIM
		*/

#ifdef _FFR_MULTIPLE_SIGNATURES
		if (dfc->mctx_signing && dfc->mctx_srhead != NULL)
		{
			status = dkimf_msr_eom(dfc->mctx_srhead);
		}
		else
		{
#endif /* _FFR_MULTIPLE_SIGNATURES */
		status = dkim_eom(dfc->mctx_dkim, &testkey);
#ifdef _FFR_MULTIPLE_SIGNATURES
		}
#endif /* _FFR_MULTIPLE_SIGNATURES */
		switch (status)
		{
		  case DKIM_STAT_OK:
			if (!dfc->mctx_signing &&
			    dkimf_findheader(dfc, DKIM_SIGNHEADER, 0) != NULL)
			{
				if (conf->conf_dolog_success)
				{
					syslog(LOG_INFO,
					       "%s DKIM verification successful",
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

		  default:
			if (conf->conf_dolog)
			{
				sig = dkim_getsignature(dfc->mctx_dkim);
				if (sig != NULL)
				{
					dkimf_log_ssl_errors(dfc->mctx_jobid,
					                     (char *) dkim_sig_getselector(sig),
					                     (char *) dkim_sig_getdomain(sig));
				}
				else
				{
					dkimf_log_ssl_errors(dfc->mctx_jobid,
					                     NULL, NULL);
				}
			}

			status = dkimf_libstatus(ctx, "dkim_eom()", status);
#ifdef _FFR_CAPTURE_UNKNOWN_ERRORS
# ifdef SMFIF_QUARANTINE
			if (dfc->mctx_capture)
			{
				if (smfi_quarantine(ctx,
				                    "capture requested") != MI_SUCCESS)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s smfi_quarantine() failed",
						       dfc->mctx_jobid);
					}
				}

				status = SMFIS_ACCEPT;
			}
# endif /* ! SMFIF_QUARANTINE */
#endif /* _FFR_CAPTURE_UNKNOWN_ERRORS */
			return status;
		}

#ifdef _FFR_STATS
		if ((status == DKIM_STAT_OK || status == DKIM_STAT_BADSIG) &&
		    !dfc->mctx_signing && conf->conf_statspath != NULL)
		{
			_Bool tmp_lengths = FALSE;
			dkim_alg_t tmp_signalg = DKIM_SIGN_UNKNOWN;
			dkim_canon_t tmp_hdrcanon = DKIM_CANON_UNKNOWN;
			dkim_canon_t tmp_bodycanon = DKIM_CANON_UNKNOWN;
			off_t signlen;
			const char *tmp_signdomain = NULL;

			sig = dkim_getsignature(dfc->mctx_dkim);
			(void) dkim_sig_getsignalg(sig, &tmp_signalg);
			(void) dkim_sig_getcanons(sig, &tmp_hdrcanon,
			                          &tmp_bodycanon);
			(void) dkim_sig_getcanonlen(dfc->mctx_dkim, sig,
			                            NULL, NULL, &signlen);
			tmp_lengths = (signlen != (off_t) -1);
			tmp_signdomain = dkim_sig_getdomain(sig);

			dkimf_stats_record(conf->conf_statspath,
			                   tmp_signdomain,
			                   tmp_hdrcanon,
			                   tmp_bodycanon,
			                   tmp_signalg,
			                   (status == DKIM_STAT_OK),
			                   testkey,
			                   tmp_lengths);
		}
#endif /* _FFR_STATS */

#ifdef _FFR_ZTAGS
		if (conf->conf_diagdir != NULL &&
		    dfc->mctx_status == DKIMF_STATUS_BAD)
		{
			int nhdrs;
			char *ohdrs[MAXHDRCNT];

			nhdrs = MAXHDRCNT;
			memset(ohdrs, '\0', sizeof ohdrs);

			sig = dkim_getsignature(dfc->mctx_dkim);

			status = dkim_ohdrs(dfc->mctx_dkim, sig,
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
						       "%s %s: fopen(): %s",
						       dfc->mctx_jobid,
						       dpath, strerror(errno));
					}
				}
				else
				{
					int c;
# ifdef _FFR_DIFFHEADERS
					int ndiffs;
					struct dkim_hdrdiff *diffs;
# endif /* _FFR_DIFFHEADERS */
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

# ifdef _FFR_DIFFHEADERS
					/* XXX -- make the "5" configurable */
					status = dkim_diffheaders(dfc->mctx_dkim,
					                          5,
					                          ohdrs,
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
					}
# endif /* _FFR_DIFFHEADERS */

					fclose(f);
				}
			}
		}	
#endif /* _FFR_ZTAGS */

		if (dfc->mctx_status == DKIMF_STATUS_GOOD)
		{
			if (conf->conf_sigmin > 0)
			{
				off_t canonlen;
				off_t bodylen;

				sig = dkim_getsignature(dfc->mctx_dkim);
				(void) dkim_sig_getcanonlen(dfc->mctx_dkim,
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

		/* compute and insert the signature, if we're signing */
		if (dfc->mctx_signing)
		{
			size_t len;
			u_char *start;

			if (dfc->mctx_tmpstr == NULL)
			{
				dfc->mctx_tmpstr = dkimf_dstring_new(BUFRSZ, 0);

				if (dfc->mctx_tmpstr == NULL)
				{
					syslog(LOG_WARNING,
					       "%s dkimf_dstring_new() failed",
					       dfc->mctx_jobid);

					return SMFIS_TEMPFAIL;
				}
			}
			else
			{
				dkimf_dstring_blank(dfc->mctx_tmpstr);
			}

			if (cc->cctx_noleadspc)
				dkimf_dstring_cat1(dfc->mctx_tmpstr, ' ');

#ifdef _FFR_MULTIPLE_SIGNATURES
			if (dfc->mctx_srhead != NULL)
			{
				struct signreq *sr;

				for (sr = dfc->mctx_srhead;
				     sr != NULL;
				     sr = sr->srq_next)
				{
					status = dkim_getsighdr_d(sr->srq_dkim,
				                                  strlen(DKIM_SIGNHEADER) + 2),
				                                  &start, &len);
					if (status != DKIM_STAT_OK)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_ERR,
							       "%s dkim_getsighdr() failed",
							       dfc->mctx_jobid);
						}

						return SMFIS_TEMPFAIL;
					}

					dkimf_stripcr(start);
					dkimf_dstring_cat(dfc->mctx_tmpstr,
					                  start);

					if (dkimf_insheader(ctx, 1,
					                    DKIM_SIGNHEADER,
					                    dkimf_dstring_get(dfc->mctx_tmpstr)) == MI_FAILURE)
					{
						if (conf->conf_dolog)
						{
							syslog(LOG_ERR,
							       "%s \"%s\" header add failed",
							       dfc->mctx_jobid,
							       DKIM_SIGNHEADER);
						}
					}
				}
			}
			else
			{
#endif /* _FFR_MULTIPLE_SIGNATURES */
			status = dkim_getsighdr_d(dfc->mctx_dkim,
			                          strlen(DKIM_SIGNHEADER) + 2,
			                          &start, &len);
			if (status != DKIM_STAT_OK)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s dkim_getsighdr() failed",
					       dfc->mctx_jobid);
				}

				return SMFIS_TEMPFAIL;
			}

			dkimf_stripcr(start);
			dkimf_dstring_cat(dfc->mctx_tmpstr, start);

			if (dkimf_insheader(ctx, 1, DKIM_SIGNHEADER,
			                    dkimf_dstring_get(dfc->mctx_tmpstr)) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s \"%s\" header add failed",
					       dfc->mctx_jobid,
					       DKIM_SIGNHEADER);
				}
			}
#ifdef _FFR_MULTIPLE_SIGNATURES
			}
#endif /* _FFR_MULTIPLE_SIGNATURES */

			if (conf->conf_dolog_success)
			{
				syslog(LOG_INFO, "%s \"%s\" header added",
				       dfc->mctx_jobid, DKIM_SIGNHEADER);
			}

#ifdef _FFR_VBR
			/* generate and add a VBR-Info header */
			memset(header, '\0', sizeof header);

			status = vbr_getheader(dfc->mctx_vbr, header,
			                       sizeof header);
			/* XXX -- log errors */
			if (status == DKIM_STAT_OK)
			{
				if (dkimf_insheader(ctx, 1, VBR_INFOHEADER,
				                    header) == MI_FAILURE)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s \"%s\" header add failed",
						       dfc->mctx_jobid,
						       VBR_INFOHEADER);
					}
				}
			}
#endif /* _FFR_VBR */
		}
	}

	if (dfc->mctx_dkim != NULL && !dfc->mctx_signing)
	{
#ifdef USE_UNBOUND
		sig = dkim_getsignature(dfc->mctx_dkim);
		if (sig != NULL)
			dfc->mctx_dnssec_key = dkim_sig_getdnssec(sig);
#endif /* USE_UNBOUND */

		/*
		**  Evaluate sender signing policy for failed or unsigned
		**  messages.
		*/

		if (dfc->mctx_status != DKIMF_STATUS_UNKNOWN)
		{
			_Bool localadsp = FALSE;
			int localresult = DKIM_PRESULT_NONE;

			if (conf->conf_localadsp_domain != NULL)
			{
				u_char *domain;

				domain = dkim_getdomain(dfc->mctx_dkim);

				if (dkimf_local_adsp(conf, (char *) domain,
				                     &pcode))
				{
					status = DKIM_STAT_OK;
					dfc->mctx_policy = TRUE;
					localadsp = TRUE;
					localresult = DKIM_PRESULT_AUTHOR;
				}
			}

			if (!dfc->mctx_policy)
			{
				status = dkim_policy(dfc->mctx_dkim, &pcode,
				                     NULL);
#ifdef USE_UNBOUND
				dfc->mctx_dnssec_policy = dkim_policy_getdnssec(dfc->mctx_dkim);
#endif /* USE_UNBOUND */
			}

			if (status == DKIM_STAT_OK)
			{
				dfc->mctx_policy = TRUE;

				if (localadsp)
					presult = localresult;
				else
					presult = dkim_getpresult(dfc->mctx_dkim);

#ifdef USE_UNBOUND
				/* special handling for sketchy answers */
				if (dfc->mctx_dnssec_policy == DKIM_DNSSEC_BOGUS &&
				    conf->conf_boguspolicy == DKIM_POLICYACTIONS_IGNORE)
					presult = DKIM_PRESULT_NONE;

				if (dfc->mctx_dnssec_policy == DKIM_DNSSEC_INSECURE &&
				    conf->conf_insecurepolicy == DKIM_POLICYACTIONS_IGNORE)
					presult = DKIM_PRESULT_NONE;
#endif /* USE_UNBOUND */

				/*
				**  Reject the message if the policy check
				**  reported NXDOMAIN and "ADSPNoSuchDomain"
				**  was enabled.
				*/

				if (presult == DKIM_PRESULT_NXDOMAIN &&
				    conf->conf_adspnxdomain)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_NOTICE,
						       "%s sender domain does not exist",
						       dfc->mctx_jobid);
					}

					if (dkimf_setreply(ctx,
					                   ADSPNXDOMAINSMTP,
					                   ADSPNXDOMAINESC,
					                   ADSPNXDOMAINTEXT) != MI_SUCCESS &&
					    conf->conf_dolog)
					{
						syslog(LOG_NOTICE,
						       "%s smfi_setreply() failed",
						       dfc->mctx_jobid);
					}

					dkimf_cleanup(ctx);
					return SMFIS_REJECT;
				}

				/*
				**  Reject the message if the policy check
				**  returned an "all" or "discardable"
				**  policy, there was no valid author
				**  signature, and "ADSPDiscard" was enabled.
				*/

				if ((pcode == DKIM_POLICY_DISCARDABLE ||
				     pcode == DKIM_POLICY_ALL) &&
				    presult == DKIM_PRESULT_AUTHOR &&
				    !dkimf_authorsigok(dfc))
				{
					dfc->mctx_susp = TRUE;
					dfc->mctx_addheader = TRUE;
				}

				if (dfc->mctx_susp && conf->conf_adspdiscard &&
				    pcode == DKIM_POLICY_DISCARDABLE)
				{
					char replybuf[BUFRSZ];
					char smtpprefix[BUFRSZ];

					if (conf->conf_dolog)
					{
						syslog(LOG_NOTICE,
						       "%s rejected per sender domain policy",
						       dfc->mctx_jobid);
					}
					
					memset(smtpprefix, '\0',
					       sizeof smtpprefix);
					(void) dkim_policy_getreportinfo(dfc->mctx_dkim,
					                                 NULL,
					                                 0,
					                                 NULL,
					                                 0,
					                                 NULL,
					                                 0,
					                                 (u_char *) smtpprefix,
					                                 sizeof smtpprefix,
					                                 NULL);

					if (smtpprefix[0] == '\0')
					{
						strlcpy(replybuf,
						           ADSPDENYTEXT,
						           sizeof replybuf);
					}
					else
					{
						snprintf(replybuf,
						         sizeof replybuf,
						         "%s: %s",
						         smtpprefix,
						         ADSPDENYTEXT);
					}

					if (dkimf_setreply(ctx,
					                   ADSPDENYSMTP,
					                   ADSPDENYESC,
					                   replybuf) != MI_SUCCESS &&
					    conf->conf_dolog)
					{
						syslog(LOG_NOTICE,
						       "%s smfi_setreply() failed",
						       dfc->mctx_jobid);
					}

					dkimf_cleanup(ctx);
					return SMFIS_REJECT;
				}
			}
			else if (conf->conf_dolog)
			{
				const char *err;

				err = dkim_geterror(dfc->mctx_dkim);
				if (err != NULL)
				{
					syslog(LOG_ERR, "%s ADSP query: %s",
					       dfc->mctx_jobid, err);
				}
			}
		}
	}

	/* insert DKIM status */
	if (dfc->mctx_addheader && dfc->mctx_status != DKIMF_STATUS_UNKNOWN)
	{
		_Bool test;
		_Bool authorsig;
		_Bool first;
		int len;
		u_int keybits;
		char *p;
		char *last;
		char *authresult;
		char *failstatus;
		char comment[BUFRSZ + 1];
		char tmphdr[DKIM_MAXHEADER + 1];

		memset(comment, '\0', sizeof comment);

		test = FALSE;
		failstatus = (testkey ? "neutral" : "fail");

#ifdef USE_UNBOUND
		/* special handling for sketchy answers */
		if (dfc->mctx_dnssec_key == DKIM_DNSSEC_BOGUS)
		{
			if (conf->conf_boguskey == DKIM_KEYACTIONS_FAIL)
			{
				dfc->mctx_status = DKIMF_STATUS_BAD;
			}
			else if (conf->conf_boguskey == DKIM_KEYACTIONS_NEUTRAL)			{
				dfc->mctx_status = DKIMF_STATUS_VERIFYERR;
				failstatus = "neutral";
			}
		}

		if (dfc->mctx_dnssec_key == DKIM_DNSSEC_INSECURE)
		{
			if (conf->conf_insecurekey == DKIM_KEYACTIONS_FAIL)
			{
				dfc->mctx_status = DKIMF_STATUS_BAD;
			}
			else if (conf->conf_insecurekey == DKIM_KEYACTIONS_NEUTRAL)
			{
				dfc->mctx_status = DKIMF_STATUS_VERIFYERR;
				failstatus = "neutral";
			}
		}
#endif /* USE_UNBOUND */

		switch (dfc->mctx_status)
		{
		  case DKIMF_STATUS_GOOD:
			authresult = "pass";
			sig = dkim_getsignature(dfc->mctx_dkim);
			assert(sig != NULL);
			(void) dkim_sig_getkeysize(sig, &keybits);
			snprintf(comment, sizeof comment, "%u-bit key",
			         keybits);
#ifdef USE_UNBOUND
			switch (dfc->mctx_dnssec_key)
			{
			  case DKIM_DNSSEC_BOGUS:
				strlcat(comment, "; bogus key",
				           sizeof comment);
				authresult = "fail";
				break;

			  case DKIM_DNSSEC_INSECURE:
				strlcat(comment, "; insecure key",
				           sizeof comment);
				break;

			  case DKIM_DNSSEC_SECURE:
				strlcat(comment, "; secure key",
				           sizeof comment);
				break;

			  default:
				break;
			}
#endif /* USE_UNBOUND */
			break;

		  case DKIMF_STATUS_NOSIGNATURE:
			authresult = "none";
			strlcpy(comment, "no signature", sizeof comment);

			if (!dfc->mctx_susp && !conf->conf_alwaysaddar)
				dfc->mctx_addheader = FALSE;

			break;

		  case DKIMF_STATUS_BAD:
		  case DKIMF_STATUS_REVOKED:
		  case DKIMF_STATUS_PARTIAL:
		  case DKIMF_STATUS_VERIFYERR:
			authresult = failstatus;
			if (dfc->mctx_status == DKIMF_STATUS_REVOKED)
			{
				strlcpy(comment, "revoked", sizeof comment);
			}
			else if (dfc->mctx_status == DKIMF_STATUS_PARTIAL)
			{
				authresult = "permerror";

				strlcpy(comment, "partial verification",
				           sizeof comment);
			}
			else if (dfc->mctx_status == DKIMF_STATUS_VERIFYERR)
			{
				const char *err;

				authresult = "permerror";

				err = dkim_geterror(dfc->mctx_dkim);
				if (err != NULL)
				{
					snprintf(comment, sizeof comment,
					         "verification error: %s",
					         err);
				}
				else
				{
					strlcpy(comment,
					           "verification error",
					           sizeof comment);
				}
			}
			else
			{
				strlcpy(comment, "verification failed",
				           sizeof comment);
			}

#ifdef USE_UNBOUND
			switch (dfc->mctx_dnssec_key)
			{
			  case DKIM_DNSSEC_BOGUS:
				strlcat(comment, "; bogus key",
				           sizeof comment);
				authresult = "fail";
				break;

			  case DKIM_DNSSEC_INSECURE:
				strlcat(comment, "; insecure key",
				           sizeof comment);
				break;

			  case DKIM_DNSSEC_SECURE:
				strlcat(comment, "; secure key",
				           sizeof comment);
				break;

			  default:
				break;
			}
#endif /* USE_UNBOUND */

			break;

		  case DKIMF_STATUS_BADFORMAT:
			authresult = "permerror";
			strlcpy(comment, "bad format", sizeof comment);
			break;

		  default:
			authresult = "neutral";
			break;
		}

#ifdef SMFIF_QUARANTINE
		/* quarantine for "bad" results if requested */
		if (quarantine &&
		    (dfc->mctx_status == DKIMF_STATUS_BAD ||
		     dfc->mctx_status == DKIMF_STATUS_REVOKED ||
		     dfc->mctx_status == DKIMF_STATUS_PARTIAL ||
		     dfc->mctx_status == DKIMF_STATUS_VERIFYERR ||
		     (dfc->mctx_status == DKIMF_STATUS_NOSIGNATURE &&
		      dfc->mctx_addheader)))
		{
			char qreason[BUFRSZ + 1];

			snprintf(qreason, sizeof qreason,
			         "%s: %s: %s", progname, failstatus, comment);
			if (smfi_quarantine(ctx, qreason) != MI_SUCCESS)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s smfi_quarantine() failed",
					       dfc->mctx_jobid);
				}
			}
		}
#endif /* SMFIF_QUARANTINE */

		if (test)
		{
			if (comment[0] == '\0')
				strlcpy(comment, "testing", sizeof comment);
			else
				strlcat(comment, "/testing", sizeof comment);
		}

		memset(header, '\0', sizeof header);

		/*
		**  Record DKIM and ADSP results in an Authentication-Results:
		**  header.
		*/

		/* first, the DKIM bit */
		if (dfc->mctx_dkim != NULL)
		{
			char val[MAXADDRESS + 1];

			memset(val, '\0', sizeof val);
			strlcpy(val, "unknown", sizeof val);
			(void) dkim_sig_getidentity(dfc->mctx_dkim, NULL,
			                            val, sizeof val);

			snprintf((char *) header, sizeof header, "%s%s",
		        	 cc->cctx_noleadspc ? " " : "",
		        	 authservid);

			if (conf->conf_authservidwithjobid &&
			    dfc->mctx_jobid != NULL)
			{
				strlcat((char *) header, "/", sizeof header);
				strlcat((char *) header, dfc->mctx_jobid,
				        sizeof header);
			}

			strlcat((char *) header, ";", sizeof header);
			strlcat((char *) header, DELIMITER, sizeof header);
			strlcat((char *) header, "dkim=", sizeof header);
			strlcat((char *) header, authresult, sizeof header);

			if (comment[0] != '\0')
			{
				strlcat((char *) header, DELIMITER,
				        sizeof header);
				strlcat((char *) header, "(", sizeof header);
				strlcat((char *) header, comment,
				        sizeof header);
				strlcat((char *) header, ")", sizeof header);
			}

			strlcat((char *) header, DELIMITER, sizeof header);
			strlcat((char *) header, "header.i=", sizeof header);
			strlcat((char *) header, val, sizeof header);
		}

		/* now the ADSP bit, unless we couldn't get the domain */
		if (dfc->mctx_status != DKIMF_STATUS_BADFORMAT)
		{
			authorsig = dkimf_authorsigok(dfc);

			if (header[0] != '\0')
			{
				strlcat((char *) header, ";", sizeof header);
				strlcat((char *) header, DELIMITER,
				        sizeof header);
			}

			strlcat((char *) header, "x-dkim-adsp=",
			        sizeof header);

			if (!dfc->mctx_policy)
			{
				strlcat((char *) header, "temperror",
				        sizeof header);
			}
#ifdef USE_UNBOUND
			else if (dfc->mctx_dnssec_policy == DKIM_DNSSEC_BOGUS)
			{
				strlcat((char *) header, "unknown",
				        sizeof header);
			}
#endif /* USE_UNBOUND */
			else if (presult == DKIM_PRESULT_NXDOMAIN)
			{					/* nxdomain */
				strlcat((char *) header, "nxdomain",
				        sizeof header);
			}
			else if (pcode == DKIM_POLICY_NONE)
			{					/* none */
				strlcat((char *) header, "none",
				        sizeof header);
			}
			else if ((pcode == DKIM_POLICY_ALL ||
			          pcode == DKIM_POLICY_DISCARDABLE) &&
			         authorsig)
			{					/* pass */
				strlcat((char *) header, "pass",
				        sizeof header);
			}
			else if (pcode == DKIM_POLICY_UNKNOWN)
			{
				if (!authorsig)
				{				/* unknown */
					strlcat((char *) header, "unknown",
					        sizeof header);
				}
				else
				{				/* signed */
					strlcat((char *) header, "signed",
					        sizeof header);
				}
			}
			else if (pcode == DKIM_POLICY_ALL && !authorsig)
			{					/* fail */
				strlcat((char *) header, "fail",
				        sizeof header);
			}
			else if (pcode == DKIM_POLICY_DISCARDABLE &&
			         !authorsig)
			{					/* discard */
				strlcat((char *) header, "discard",
				        sizeof header);
			}

#ifdef USE_UNBOUND
			switch (dfc->mctx_dnssec_policy)
			{
			  case DKIM_DNSSEC_BOGUS:
				strlcat((char *) header, " (bogus policy)",
				        sizeof header);
				break;

			  case DKIM_DNSSEC_INSECURE:
				strlcat((char *) header, " (insecure policy)",
				        sizeof header);
				break;

			  case DKIM_DNSSEC_SECURE:
				strlcat((char *) header, " (secure policy)",
				        sizeof header);
				break;

			  default:
				break;
			}
#endif /* USE_UNBOUND */
		}

		/* if we generated either, pretty it up */
		if (header[0] != '\0')
		{
			c = sizeof AUTHRESULTSHDR + 2;
			first = TRUE;
			memset(tmphdr, '\0', sizeof tmphdr);

			for (p = strtok_r((char *) header, DELIMITER, &last);
			     p != NULL;
			     p = strtok_r(NULL, DELIMITER, &last))
			{
				len = strlen(p);

				if (!first)
				{
					if (c + len >= DKIM_HDRMARGIN)
					{
						strlcat(tmphdr, "\n\t",
						        sizeof tmphdr);
						c = 8;
					}
					else
					{
						strlcat(tmphdr, " ",
						           sizeof tmphdr);
					}
				}

				strlcat(tmphdr, p, sizeof tmphdr);
				first = FALSE;
				c += len;
			}

			if (dfc->mctx_addheader &&
			    dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
			                    tmphdr) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s \"%s\" header add failed",
					       dfc->mctx_jobid,
					       AUTHRESULTSHDR);
				}
			}
		}

		/* send an ARF message for DKIM? */
		if (dfc->mctx_dkim != NULL)
		{
			if (dfc->mctx_status == DKIMF_STATUS_BAD &&
			    conf->conf_sendreports)
				dkimf_sigreport(dfc, conf, hostname);
		}

		/* send an ARF message for ADSP? */
		if (dfc->mctx_susp && conf->conf_sendadspreports)
			dkimf_policyreport(dfc, conf, hostname);
	}

#ifdef _FFR_VBR
	if (!dfc->mctx_signing &&
	    dkimf_findheader(dfc, VBR_INFOHEADER, 0) != NULL)
	{
		_Bool add_vbr_header = FALSE;
		VBR_STAT vbr_status;
		int c;
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
		Header vbr_header;
		char tmp[DKIM_MAXHEADER + 1];

		for (c = 0; ; c++)
		{
			vbr_header = dkimf_findheader(dfc, VBR_INFOHEADER, c);
			if (vbr_header == NULL)
				break;

			vbr_result = NULL;
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

				for (param = p; *param != '\0'; param++)
				{
					if (!(isascii(*param) &&
					      isspace(*param)))
						break;
				}
				dkimf_trimspaces(param);

				for (value = eq + 1; *value != '\0'; value++)
				{
					if (!(isascii(*value) &&
					      isspace(*value)))
						break;
				}
				dkimf_trimspaces(value);

				if (strcasecmp(param, "md") == 0)
				{
					vbr_domain = value;
				}
				else if (strcasecmp(param, "mc") == 0)
				{
					vbr_type = value;
				}
				else if (strcasecmp(param, "mv") == 0)
				{
					vbr_vouchers = value;
				}
			}
			
			/* use accessors to set parsed values */
			vbr_setcert(dfc->mctx_vbr, vbr_vouchers);
			vbr_settype(dfc->mctx_vbr, vbr_type);
			vbr_setdomain(dfc->mctx_vbr, vbr_domain);
		
			/* attempt the query */
			vbr_status = vbr_query(dfc->mctx_vbr, &vbr_result,
			                       &vbr_certifier);
			switch (vbr_status)
			{
			  case VBR_STAT_DNSERROR:
				if (conf->conf_dolog)
				{
					const char *err;

					err = vbr_geterror(dfc->mctx_vbr);

					syslog(LOG_NOTICE,
					       "%s: can't verify VBR information%s%s",
					       dfc->mctx_jobid,
					       err == NULL ? "" : ": ",
					       err == NULL ? "" : err);
				}
				vbr_result = "neutral";
				break;

			  case VBR_STAT_INVALID:
			  case VBR_STAT_NORESOURCE:
				if (conf->conf_dolog)
				{
					const char *err;

					err = vbr_geterror(dfc->mctx_vbr);

					syslog(LOG_NOTICE,
					       "%s: error handling VBR information%s%s",
					       dfc->mctx_jobid,
					       err == NULL ? "" : ": ",
					       err == NULL ? "" : err);
				}
				vbr_result = "neutral";
				break;

			  case DKIM_STAT_OK:
				add_vbr_header = TRUE;
				break;

			  default:
				assert(0);
			}

			if (add_vbr_header)
			{
				char hdr[DKIM_MAXHEADER + 1];

				memset(hdr, '\0', sizeof hdr);

				snprintf(hdr, sizeof hdr, "%s.md",
				         VBR_INFOHEADER);
				dkimf_lowercase(hdr);
				snprintf(header, sizeof header,
				         "%s%s%s%s vbr=%s%s%s%s header.%s=%s",
				         cc->cctx_noleadspc ? " " : "",
				         authservid,
				         conf->conf_authservidwithjobid ? "/"
				                                        : "",
				         conf->conf_authservidwithjobid ? dfc->mctx_jobid
				                                        : "",
				         vbr_certifier == NULL ? "" : " (",
				         vbr_certifier == NULL ? "" : vbr_certifier,
				         vbr_certifier == NULL ? "" : ")",
				         hdr, vbr_domain, vbr_result);
		
				if (dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
				                    header) == MI_FAILURE)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s \"%s\" header add failed",
						       dfc->mctx_jobid,
						       AUTHRESULTSHDR);
					}
				}

				break;
			}
		}
	}
#endif /* _FFR_VBR */

#if VERIFY_DOMAINKEYS
	if (dfc->mctx_dk != NULL)
	{
		DK_FLAGS flags;
		char *authresult = NULL;
		char *comment = NULL;
		char hdr[DKIM_MAXHEADER + 1];
		char val[MAXADDRESS + 1];

		flags = 0;
		dfc->mctx_addheader = FALSE;

		status = dk_eom(dfc->mctx_dk, &flags);
		switch (status)
		{
		  case DK_STAT_OK:
			dfc->mctx_addheader = dfc->mctx_dksigned;
			authresult = "pass";
			break;

		  case DK_STAT_BADSIG:
			dfc->mctx_addheader = TRUE;
			authresult = "fail";
			break;

		  case DK_STAT_NOSIG:
			/* XXX -- extract policy */
			dfc->mctx_addheader = TRUE;
			authresult = "neutral";
			comment = "no signature";
			break;

		  case DK_STAT_NOKEY:
			/* XXX -- extract policy */
			dfc->mctx_addheader = TRUE;
			authresult = "neutral";
			comment = "no key";
			break;

		  default:
			/* XXX -- do better? */
			if (conf->conf_dolog)
			{
#if (DK_LIB_VERSION >= 0x00050000)
				const char *err;

				err = dk_geterror(dfc->mctx_dk);
				if (err == NULL)
					err = strerror(errno);

				syslog(LOG_INFO,
				       "%s dk_eom() returned status %d: %s",
				       dfc->mctx_jobid, status, err);
#else /* (DK_LIB_VERSION >= 0x00050000) */
				syslog(LOG_INFO,
				       "%s dk_eom() returned status %d",
				       dfc->mctx_jobid, status);
#endif /* (DK_LIB_VERSION >= 0x00050000) */
			}
			break;
		}

		if (dfc->mctx_addheader)
		{
			strlcpy(hdr, "unknown", sizeof hdr);
			strlcpy(val, "unknown", sizeof val);

			(void) dk_getidentity(dfc->mctx_dk, hdr, sizeof hdr,
			                      val, sizeof val);

			memset(header, '\0', sizeof header);

			snprintf(header, sizeof header,
			         "%s%s%s%s; domainkeys=%s%s%s%s%s header.%s=%s",
			         cc->cctx_noleadspc ? " " : "",
			         authservid,
			         conf->conf_authservidwithjobid ? "/" : "",
			         conf->conf_authservidwithjobid ? dfc->mctx_jobid
			                                        : "",
			         authresult,
			         comment == NULL ? "" : " (",
			         comment == NULL ? "" : comment,
			         comment == NULL ? "" : ")",
			         !(flags & DK_FLAG_TESTING) ? "" : " (testing)",
			         hdr, val);

			if (dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
			                    header) == MI_FAILURE)
			{
				if (conf->conf_dolog)
				{
					syslog(LOG_ERR,
					       "%s \"%s\" header add failed",
					       dfc->mctx_jobid,
					       AUTHRESULTSHDR);
				}
			}
		}
	}
#endif /* VERIFY_DOMAINKEYS */

#ifdef _FFR_DKIM_REPUTATION
	if (dfc->mctx_status == DKIMF_STATUS_GOOD && !dfc->mctx_signing)
	{
		int rep = 0;

		sig = dkim_getsignature(dfc->mctx_dkim);

		if (sig != NULL)
		{
			char *qroot;

			if (conf->conf_reproot == NULL)
				qroot = DKIM_REP_ROOT;
			else
				qroot = conf->conf_reproot;

			status = dkim_get_reputation(dfc->mctx_dkim, sig,
			                             qroot, &rep);

			if (status == DKIM_STAT_CANTVRFY ||
			    status == DKIM_STAT_INTERNAL)
			{
				syslog(LOG_INFO,
				       "%s error during reputation query",
				       dfc->mctx_jobid);
			}
			else if (rep > conf->conf_repreject)
			{
				if (dkimf_setreply(ctx,
				                   REPDENYSMTP,
				                   REPDENYESC,
				                   REPDENYTXT) != MI_SUCCESS &&
				    conf->conf_dolog)
				{
					syslog(LOG_NOTICE,
					       "%s smfi_setreply() failed",
					       dfc->mctx_jobid);
				}

				dkimf_cleanup(ctx);
				return SMFIS_REJECT;
			}
			else
			{
				char *result;

				if (rep > conf->conf_repfail)
					result = "fail";
				else if (rep < conf->conf_reppass)
					result = "pass";
				else
					result = "neutral";

				snprintf(header, sizeof header,
				        "%s%s%s%s; x-dkim-rep=%s (%d) header.d=%s",
				         cc->cctx_noleadspc ? " " : "",
				         authservid,
				         conf->conf_authservidwithjobid ? "/" : "",
				         conf->conf_authservidwithjobid ? dfc->mctx_jobid
				                                        : "",
				         result, rep,
				         dkim_sig_getdomain(sig));

				if (dkimf_insheader(ctx, 1, AUTHRESULTSHDR,
				                    header) == MI_FAILURE)
				{
					if (conf->conf_dolog)
					{
						syslog(LOG_ERR,
						       "%s \"%s\" header add failed",
						       dfc->mctx_jobid,
						       AUTHRESULTSHDR);
					}
				}
			}
		}
	}
#endif /* _FFR_DKIM_REPUTATION */

	/*
	**  Identify the filter, if requested.
	*/

	if (conf->conf_addxhdr)
	{
		char xfhdr[DKIM_MAXHEADER + 1];

		memset(xfhdr, '\0', sizeof xfhdr);

		snprintf(xfhdr, DKIM_MAXHEADER, "%s%s v%s %s %s",
		         cc->cctx_noleadspc ? " " : "",
		         DKIMF_PRODUCT, DKIMF_VERSION, hostname,
		         dfc->mctx_jobid != NULL ? dfc->mctx_jobid
		                                : JOBIDUNKNOWN);

		if (dkimf_insheader(ctx, 1, XHEADERNAME, xfhdr) != MI_SUCCESS)
		{
			if (conf->conf_dolog)
			{
				syslog(LOG_ERR, "%s \"%s\" header add failed",
				       dfc->mctx_jobid, XHEADERNAME);
			}

			dkimf_cleanup(ctx);
			return SMFIS_TEMPFAIL;
		}
	}

	if (sig == NULL)
	{
		dkimf_log_ssl_errors(dfc->mctx_jobid, NULL, NULL);
	}
	else
	{
		dkimf_log_ssl_errors(dfc->mctx_jobid,
		                     (char *) dkim_sig_getselector(sig),
		                     (char *) dkim_sig_getdomain(sig));
	}

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
		ret = dkimf_libstatus(ctx, "mlfi_eom()", DKIM_STAT_BADSIG);
		if ((ret == SMFIS_REJECT || ret == SMFIS_TEMPFAIL ||
		     ret == SMFIS_DISCARD) &&
		    testkey)
			ret = SMFIS_ACCEPT;
		break;

	  case DKIMF_STATUS_NOKEY:
		ret = dkimf_libstatus(ctx, "mlfi_eom()", DKIM_STAT_NOKEY);
		break;

	  case DKIMF_STATUS_REVOKED:
		ret = SMFIS_TEMPFAIL;
		break;

	  case DKIMF_STATUS_NOSIGNATURE:
		if (!dfc->mctx_addheader)
		{
			ret = dkimf_libstatus(ctx, "mlfi_eom()",
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
			ret = dkimf_libstatus(ctx, "mlfi_eom()", status);
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

			dkim_getcachestats(&c_queries, &c_hits, &c_expired);

			cache_lastlog = now;

			syslog(LOG_INFO,
			       "cache: %u quer%s, %u hit%s (%d%%), %u expired",
			       c_queries, c_queries == 1 ? "y" : "ies",
			       c_hits, c_hits == 1 ? "" : "s",
			       (c_hits * 100) / c_queries,
			       c_expired);
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
	(SMFIF_ADDHDRS | SMFIF_CHGHDRS |
#ifdef SMFIF_QUARANTINE
	 SMFIF_QUARANTINE |
#endif /* SMFIF_QUARANTINE */
#ifdef SMFIF_SETSYMLIST
	 SMFIF_SETSYMLIST |
#endif /* SMFIF_SETSYMLIST */
	 0),		/* flags */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
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
	                "\t-a peerlist \tfile containing list of hosts to ignore\n"
	                "\t-A          \tauto-restart\n"
	                "\t-b modes    \tselect operating modes\n"
	                "\t-c canon    \tcanonicalization to use when signing\n"
	                "\t-C config   \taction configuration info (see man page)\n"
	                "\t-d domlist  \tdomains to sign\n"
	                "\t-D          \talso sign subdomains\n"
	                "\t-f          \tdon't fork-and-exit\n"
	                "\t-F time     \tfixed timestamp to use when signing (test mode only)\n"
	                "\t-h          \tappend identifying header\n"
	                "\t-i ilist    \tfile containing list of internal (signing) hosts\n"
	                "\t-I elist    \tfile containing list of external domain clients\n"
	                "\t-k keyfile  \tlocation of secret key file\n"
	                "\t-K          \tload a key set instead of a single key\n"
	                "\t-l          \tlog activity to system log\n"
	                "\t-L limit    \tsignature limit requirements\n"
	                "\t-m mtalist  \tMTA daemon names for which to sign\n"
	                "\t-M macrolist\tMTA macros which enable signing\n"
			"\t-o hdrlist  \tlist of headers to omit from signing\n"
	                "\t-P pidfile  \tfile to which to write pid\n"
	                "\t-r          \trequire basic RFC2822 header compliance\n"
	                "\t-R          \tgenerate verification failure reports\n"
	                "\t-s selector \tselector to use when signing\n"
	                "\t-S signalg  \tsignature algorithm to use when signing\n"
			"\t-t testfile \tevaluate RFC2822 message in \"testfile\"\n"
			"\t-T timeout  \tDNS timeout (seconds)\n"
	                "\t-u userid   \tchange to specified userid\n"
#if POPAUTH
			"\t-U dbfile   \tuser POP AUTH database\n"
#endif /* POPAUTH */
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
	int c;
	int status;
	int n;
	int verbose = 0;
	int maxrestarts = 0;
	int maxrestartrate_n = 0;
	int filemask = -1;
	int mdebug = 0;
	sigset_t sigset;
	time_t fixedtime = (time_t) -1;
	time_t maxrestartrate_t = 0;
	pthread_t rt;
	unsigned long tmpl;
	const char *args = CMDLINEOPTS;
	FILE *f;
	char *become = NULL;
	char *p;
	char *pidfile = NULL;
#if POPAUTH
	char *popdbfile = NULL;
#endif /* POPAUTH */
#if _FFR_BODYLENGTH_DB
	char *bldbfile = NULL;
#endif /* _FFR_BODYLENGTH_DB  */
#if _FFR_REPORT_INTERVALS
	char *ridbfile = NULL;
#endif /* _FFR_REPORT_INTERVALS  */
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
#if POPAUTH
	popdb = NULL;
#endif /* POPAUTH */
#ifdef _FFR_BODYLENGTH_DB
	bldb = NULL;
#endif /* _FFR_BODYLENGTH_DB */
#ifdef _FFR_REPORT_INTERVALS
	ridb = NULL;
#endif /* _FFR_REPORT_INTERVALS */
	no_i_whine = TRUE;
	quarantine = FALSE;
	conffile = NULL;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

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
		  case 'a':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_peerfile = optarg;
			break;

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

		  case 'C':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_actions = optarg;
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

			if (fixedtime == (time_t) ULONG_MAX || errno != 0 ||
			    *p != '\0')
			{
				fprintf(stderr, "%s: invalid time value\n",
				        progname);
				return EX_USAGE;
			}
			break;

		  case 'h':
			curconf->conf_addxhdr = TRUE;
			break;

		  case 'i':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_internalfile = optarg;
			break;

		  case 'I':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_externalfile = optarg;
			break;

		  case 'k':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_keyfile = optarg;
			break;

		  case 'K':
			curconf->conf_multikey = TRUE;
			break;

		  case 'l':
			curconf->conf_dolog = TRUE;
			break;

		  case 'L':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_siglimit = optarg;
			break;

		  case 'm':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_mtalist = strdup(optarg);
			if (curconf->conf_mtalist == NULL)
			{
				fprintf(stderr, "%s: strdup(): %s\n", progname,
				        strerror(errno));
				return EX_SOFTWARE;
			}
			break;

		  case 'M':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_macrolist = strdup(optarg);
			if (curconf->conf_macrolist == NULL)
			{
				fprintf(stderr, "%s: strdup(): %s\n", progname,
				        strerror(errno));
				return EX_SOFTWARE;
			}
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

		  case 'q':
			quarantine = TRUE;
			break;

		  case 'r':
			curconf->conf_reqhdrs = TRUE;
			break;

		  case 'R':
			curconf->conf_sendreports = TRUE;
			break;

		  case 's':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			curconf->conf_selector = optarg;
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

			if (tmpl > UINT_MAX || errno != 0 || *p != '\0')
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

#if POPAUTH
		  case 'U':
			if (optarg == NULL || *optarg == '\0')
				return usage();
			popdbfile = optarg;
			break;
#endif /* POPAUTH */

		  case 'v':
			verbose++;
			break;

		  case 'V':
			printf("%s: %s v%s\n", progname, DKIMF_PRODUCT,
			       DKIMF_VERSION);
			printf("\tCompiled with %s\n",
			       SSLeay_version(SSLEAY_VERSION));
			printf("\tSupported signing algorithms:\n");
			for (c = 0; dkimf_sign[c].str != NULL; c++)
				printf("\t\t%s\n", dkimf_sign[c].str);
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

		  default:
			return usage();
		}
	}

	if (optind != argc)
		return usage();

	if (dkim_ssl_version() != OPENSSL_VERSION_NUMBER)
	{
		fprintf(stderr,
		        "%s: incompatible OpenSSL versions (library = 0x%09lx, filter = %09lx)\n",
		        progname, dkim_ssl_version(), OPENSSL_VERSION_NUMBER);

		return EX_SOFTWARE;
	}

	if (conffile != NULL)
	{
		u_int line = 0;
		char *missing;
		char path[MAXPATHLEN + 1];

		cfg = config_load(conffile, dkimf_config,
		                  &line, path, sizeof path);

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
		config_dump(cfg, stdout);
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
	}

	if (dkimf_config_load(cfg, curconf, err, sizeof err) != 0)
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

	dolog = curconf->conf_dolog;
	curconf->conf_data = cfg;

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
			char *rate;

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

		if (!quarantine)
		{
			(void) config_get(cfg, "Quarantine", &quarantine,
			                  sizeof quarantine);
		}

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

#ifdef _FFR_BODYLENGTH_DB
		if (bldbfile == NULL)
		{
			(void) config_get(cfg, "BodyLengthDBFile",
			                  &bldbfile, sizeof bldbfile);
		}
#endif /* _FFR_BODYLENGTH_DB */

#ifdef _FFR_REPORT_INTERVALS
		if (ridbfile == NULL)
		{
			(void) config_get(cfg, "ReportIntervalDB",
			                  &ridbfile, sizeof ridbfile);
		}
#endif /* _FFR_REPORT_INTERVALS */

#if POPAUTH
		if (popdbfile == NULL)
		{
			(void) config_get(cfg, "POPDBFile", &popdbfile,
			                  sizeof popdbfile);
		}
#endif /* POPAUTH */
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
	}

	dkimf_setmaxfd();

	/* change user if appropriate */
	if (become != NULL)
	{
		gid_t gid;
		char *colon;
		struct passwd *pw;
		struct group *gr = NULL;

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
						       "no such group or gid `%s'",
						       colon + 1);
					}

					fprintf(stderr,
					        "%s: no such group `%s'\n",
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
					       "no such user or uid `%s'",
					       become);
				}

				fprintf(stderr, "%s: no such user `%s'\n",
				        progname, become);

				return EX_DATAERR;
			}
		}

		if (gr == NULL)
			gid = pw->pw_gid;
		else
			gid = gr->gr_gid;

		/* make all the process changes */
		if (getuid() != pw->pw_uid)
		{
			if (initgroups(pw->pw_name, gid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "initgroups(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: initgroups(): %s\n",
				        progname, strerror(errno));

				return EX_NOPERM;
			}
			else if (setgid(gid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "setgid(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: setgid(): %s\n", progname,
				        strerror(errno));

				return EX_NOPERM;
			}
			else if (setuid(pw->pw_uid) != 0)
			{
				if (curconf->conf_dolog)
				{
					syslog(LOG_ERR, "setuid(): %s",
					       strerror(errno));
				}

				fprintf(stderr, "%s: setuid(): %s\n", progname,
				        strerror(errno));

				return EX_NOPERM;
			}
		}

		(void) endpwent();
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
		sa.sa_flags = 0;

		if (sigaction(SIGHUP, &sa, NULL) != 0 ||
		    sigaction(SIGINT, &sa, NULL) != 0 ||
		    sigaction(SIGTERM, &sa, NULL) != 0)
		{
			if (curconf->conf_dolog)
			{
				syslog(LOG_ERR, "[parent] sigaction(): %s",
				       strerror(errno));
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
							syslog(LOG_NOTICE,
							       "exited with status %d, restarting",
							       WEXITSTATUS(status));
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

	/* initialize libcrypto mutexes */
	status = dkimf_crypto_init();
	if (status != 0)
	{
		fprintf(stderr, "%s: error initializing crypto library: %s\n",
		        progname, strerror(status));
	}

	/* initialize DKIM library */
	if (!dkimf_config_setlib(curconf))
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_WARNING,
			       "can't configure DKIM library; continuing");
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

#if VERIFY_DOMAINKEYS
	libdk = dk_init(NULL, NULL);
	if (libdk == NULL)
	{
		if (curconf->conf_dolog)
			syslog(LOG_ERR, "can't initialize DK library");

		if (!autorestart && pidfile != NULL)
			(void) unlink(pidfile);

		return EX_UNAVAILABLE;
	}
#endif /* VERIFY_DOMAINKEYS */

#if _FFR_BODYLENGTH_DB
	if (bldbfile != NULL)
	{
		status = dkimf_db_open_ro(&bldb, bldbfile);
		if (status != 0)
		{
			fprintf(stderr, "%s: can't open database %s: %s\n",
			        progname, bldbfile, DB_STRERROR(status));
			if (dolog)
			{
				syslog(LOG_ERR, "can't open database %s",
				       bldbfile);
			}
			dkimf_zapkey(curconf);

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

		status = pthread_mutex_init(&bldb_lock, NULL);
		if (status != 0)
		{
			fprintf(stderr,
			        "%s: can't initialize body length DB mutex: %s\n",
			        progname, strerror(status));
			if (dolog)
			{
				syslog(LOG_ERR,
				       "can't initialize body length DB mutex: %s",
				       strerror(status));
			}
		}
	}
#endif /* _FFR_BODYLENGTH_DB */

#if _FFR_REPORT_INTERVALS
	if (ridbfile != NULL)
	{
		status = dkimf_db_open_rw(&ridb, ridbfile);
		if (status != 0)
		{
			fprintf(stderr, "%s: can't open database %s: %s\n",
			        progname, ridbfile, DB_STRERROR(status));
			if (dolog)
			{
				syslog(LOG_ERR, "can't open database %s",
				       ridbfile);
			}
			dkimf_zapkey(curconf);

#ifdef _FFR_BODYLENGTH_DB
			if (bldb != NULL)
				DKIMF_DBCLOSE(bldb);
#endif /* _FFR_BODYLENGTH_DB */

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_UNAVAILABLE;
		}

		status = pthread_mutex_init(&ridb_lock, NULL);
		if (status != 0)
		{
			fprintf(stderr,
			        "%s: can't initialize body length DB mutex: %s\n",
			        progname, strerror(status));
			if (dolog)
			{
				syslog(LOG_ERR,
				       "can't initialize body length DB mutex: %s",
				       strerror(status));
			}
		}
	}
#endif /* _FFR_REPORT_INTERVALS */

	pthread_mutex_init(&popen_lock, NULL);
	pthread_mutex_init(&conf_lock, NULL);

	/* perform test mode */
	if (testfile != NULL)
	{
		status = dkimf_testfile(curconf->conf_libopendkim, testfile,
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

#if POPAUTH
	if (popdbfile != NULL)
	{
		status = dkimf_initpopauth();
		if (status != 0)
		{
			fprintf(stderr,
			        "%s: can't initialize popauth mutex: %s\n",
			        progname, strerror(status));
			syslog(LOG_ERR, "can't initialize mutex: %s",
			       popdbfile);
		}

		status = dkimf_db_open_ro(&popdb, popdbfile);
		if (status != 0)
		{
			fprintf(stderr, "%s: can't open database %s: %s\n",
			        progname, popdbfile, DB_STRERROR(status));

			if (dolog)
			{
				syslog(LOG_ERR, "can't open database %s",
				       popdbfile);
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
		       DKIMF_VERSION, argstr);
	}

	/* spawn the SIGUSR1 handler */
	status = pthread_create(&rt, NULL, dkimf_reloader, NULL);
	if (status != 0)
	{
		if (curconf->conf_dolog)
		{
			syslog(LOG_ERR, "pthread_create(): %s",
			       strerror(status));

			if (!autorestart && pidfile != NULL)
				(void) unlink(pidfile);

			return EX_OSERR;
		}
	}

	/* call the milter mainline */
	errno = 0;
	status = smfi_main();

	if (curconf->conf_dolog)
	{
		syslog(LOG_INFO,
		       "%s v%s terminating with status %d, errno = %d",
		       DKIMF_PRODUCT, DKIMF_VERSION, status, errno);
	}

#if _FFR_BODYLENGTH_DB
	if (bldb != NULL)
		DKIMF_DBCLOSE(bldb);
#endif /* _FFR_BODYLENGTH_DB */

#if _FFR_REPORT_INTERVALS
	if (ridb != NULL)
		DKIMF_DBCLOSE(ridb);
#endif /* _FFR_REPORT_INTERVALS */

#if POPAUTH
	if (popdb != NULL)
		DKIMF_DBCLOSE(popdb);
#endif /* POPAUTH */

	dkimf_zapkey(curconf);

	/* tell the reloader thread to die */
	die = TRUE;
	(void) raise(SIGUSR1);

	if (!autorestart && pidfile != NULL)
		(void) unlink(pidfile);

	dkimf_crypto_free();

	return status;
}
