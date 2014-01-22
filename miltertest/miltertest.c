/*
**  Copyright (c) 2009-2014, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sysexits.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>

/* libmilter includes */
#include <libmilter/mfapi.h>
#ifndef SMFI_PROT_VERSION
# define SMFI_PROT_VERSION	SMFI_VERSION
#endif /* ! SMFI_PROT_VERSION */

/* libopendkim includes */
#include <dkim.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* Lua includes */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* types */
#ifndef HAVE_USECONDS_T
typedef unsigned int useconds_t;
#endif /* ! HAVE_USECONDS_T */

/* macros */
#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

#ifdef SMFIP_NODATA
# define CHECK_MPOPTS(c,o)	(((c)->ctx_mpopts & (o)) != 0)
#else /* SMFIP_NODATA */
# define CHECK_MPOPTS(c,o)	0
#endif /* SMFIP_NODATA */

#ifndef SMFIP_NR_CONN
# define SMFIP_NR_CONN		0
# define SMFIP_NR_HELO		0
# define SMFIP_NR_MAIL		0
# define SMFIP_NR_RCPT		0
# define SMFIP_NR_DATA		0
# define SMFIP_NR_HDR		0
# define SMFIP_NR_EOH		0
# define SMFIP_NR_BODY		0
# define SMFIP_NR_UNKN		0
#endif /* SMFIP_NR_CONN */

#define	MT_PRODUCT		"OpenDKIM milter test facility"
#define	MT_VERSION		"1.6.0"

#define	BUFRSZ			1024
#define	CHUNKSZ			65536

#define	CMDLINEOPTS		"D:s:uvVw"

#define	DEFBODY			"Dummy message body.\r\n"
#define	DEFCLIENTPORT		12345
#define DEFCLIENTHOST		"test.example.com"
#define DEFCLIENTIP		"12.34.56.78"
#define	DEFHEADERNAME		"From"
#define DEFSENDER		"<sender@example.com>"
#define	DEFTIMEOUT		10
#define DEFRECIPIENT		"<recipient@example.com>"

#define	STATE_UNKNOWN		(-1)
#define	STATE_INIT		0
#define	STATE_NEGOTIATED	1
#define	STATE_CONNINFO		2
#define	STATE_HELO		3
#define	STATE_ENVFROM		4
#define	STATE_ENVRCPT		5
#define	STATE_DATA		6
#define	STATE_HEADER		7
#define	STATE_EOH		8
#define	STATE_BODY		9
#define	STATE_EOM		10
#define	STATE_DEAD		99

#define MT_HDRADD		1
#define MT_HDRINSERT		2
#define MT_HDRCHANGE		3
#define MT_HDRDELETE		4
#define MT_RCPTADD		5
#define MT_RCPTDELETE		6
#define MT_BODYCHANGE		7
#define MT_QUARANTINE		8
#define MT_SMTPREPLY		9

/* prototypes */
int mt_abort(lua_State *);
int mt_bodyfile(lua_State *);
int mt_bodyrandom(lua_State *);
int mt_bodystring(lua_State *);
int mt_chdir(lua_State *);
int mt_connect(lua_State *);
int mt_conninfo(lua_State *);
int mt_data(lua_State *);
int mt_disconnect(lua_State *);
int mt_echo(lua_State *);
int mt_eoh(lua_State *);
int mt_eom(lua_State *);
int mt_eom_check(lua_State *);
int mt_getcwd(lua_State *);
int mt_getheader(lua_State *);
int mt_getreply(lua_State *);
int mt_header(lua_State *);
int mt_helo(lua_State *);
int mt_macro(lua_State *);
int mt_mailfrom(lua_State *);
int mt_negotiate(lua_State *);
int mt_rcptto(lua_State *);
int mt_set_timeout(lua_State *);
int mt_signal(lua_State *);
int mt_sleep(lua_State *);
int mt_startfilter(lua_State *);
int mt_test_action(lua_State *);
int mt_test_option(lua_State *);
int mt_unknown(lua_State *);

/* data types */
struct mt_eom_request
{
	char		eom_request;		/* request code */
	size_t		eom_rlen;		/* request length */
	char *		eom_rdata;		/* request data */
	struct mt_eom_request * eom_next;	/* next request */
};

struct mt_context
{
	char		ctx_response;		/* milter response code */
	int		ctx_fd;			/* descriptor */
	int		ctx_state;		/* current state */
	unsigned long	ctx_mactions;		/* requested actions */
	unsigned long	ctx_mpopts;		/* requested protocol opts */
	struct mt_eom_request * ctx_eomreqs;	/* EOM requests */
};

struct mt_lua_io
{
	_Bool		lua_io_done;
	size_t		lua_io_scriptlen;
	const char *	lua_io_script;
};

static const luaL_Reg mt_library[] =
{
	{ "abort",		mt_abort	},
	{ "bodyfile",		mt_bodyfile	},
	{ "bodyrandom",		mt_bodyrandom	},
	{ "bodystring",		mt_bodystring	},
	{ "chdir",		mt_chdir	},
	{ "connect",		mt_connect	},
	{ "conninfo",		mt_conninfo	},
	{ "data",		mt_data		},
	{ "disconnect",		mt_disconnect	},
	{ "echo",		mt_echo		},
	{ "eoh",		mt_eoh		},
	{ "eom",		mt_eom		},
	{ "eom_check",		mt_eom_check	},
	{ "getcwd",		mt_getcwd	},
	{ "getheader",		mt_getheader	},
	{ "getreply",		mt_getreply	},
	{ "header",		mt_header	},
	{ "helo",		mt_helo		},
	{ "macro",		mt_macro	},
	{ "mailfrom",		mt_mailfrom	},
	{ "negotiate",		mt_negotiate	},
	{ "rcptto",		mt_rcptto	},
	{ "set_timeout",	mt_set_timeout	},
	{ "signal",		mt_signal	},
	{ "sleep",		mt_sleep	},
	{ "startfilter",	mt_startfilter	},
	{ "test_action",	mt_test_action	},
	{ "test_option",	mt_test_option	},
	{ "unknown",		mt_unknown	},
	{ NULL,			NULL 		}
};

/* globals */
_Bool rusage;
_Bool nowait;
int verbose;
unsigned int tmo;
pid_t filterpid;
char scriptbuf[BUFRSZ];
char *progname;

/*
**  MT_INET_NTOA -- thread-safe inet_ntoa()
**
**  Parameters:
**  	a -- (struct in_addr) to be converted
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Return value:
**  	Size of the resultant string.  If the result is greater than buflen,
**  	then buf does not contain the complete result.
*/

size_t
mt_inet_ntoa(struct in_addr a, char *buf, size_t buflen)
{
	in_addr_t addr;

	assert(buf != NULL);

	addr = ntohl(a.s_addr);

	return snprintf(buf, buflen, "%d.%d.%d.%d",
	                (addr >> 24), (addr >> 16) & 0xff,
	                (addr >> 8) & 0xff, addr & 0xff);
}

/*
**  MT_LUA_READER -- "read" a script and make it available to Lua
**
**  Parameters:
**  	l -- Lua state
**  	data -- pointer to a Lua I/O structure
**  	size -- size (returned)
**
**  Return value:
**  	Pointer to the data.
*/

const char *
mt_lua_reader(lua_State *l, void *data, size_t *size)
{
	struct mt_lua_io *io;

	assert(l != NULL);
	assert(data != NULL);
	assert(size != NULL);

	io = (struct mt_lua_io *) data;

	if (io->lua_io_done)
	{
		*size = 0;
		return NULL;
	}
	else if (io->lua_io_script != NULL)
	{
		io->lua_io_done = TRUE;
		*size = io->lua_io_scriptlen;
		return io->lua_io_script;
	}
	else
	{
		size_t rlen;

		memset(scriptbuf, '\0', sizeof scriptbuf);

		if (feof(stdin))
		{
			*size = 0;
			io->lua_io_done = TRUE;
			return NULL;
		}

		rlen = fread(scriptbuf, 1, sizeof scriptbuf, stdin);
		*size = rlen;
		return (const char *) scriptbuf;
	}
}

/*
**  MT_LUA_ALLOC -- allocate memory
**
**  Parameters:
**  	ud -- context (not used)
**  	ptr -- pointer (for realloc())
**  	osize -- old size
**  	nsize -- new size
**
**  Return value:
**  	Allocated memory, or NULL on failure.
*/

void *
mt_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	if (nsize == 0 && osize != 0)
	{
		free(ptr);
		return NULL;
	}
	else if (nsize != 0 && osize == 0)
	{
		return malloc(nsize);
	}
	else
	{
		return realloc(ptr, nsize);
	}
}

/*
**  MT_FLUSH_EOMREQS -- free EOM requests
**
**  Parameters:
**  	ctx -- mt_context handle
**
**  Return value:
**  	None.
*/

void
mt_flush_eomreqs(struct mt_context *ctx)
{
	struct mt_eom_request *r;

	assert(ctx != NULL);

	while (ctx->ctx_eomreqs != NULL)
	{
		r = ctx->ctx_eomreqs;
		if (r->eom_rdata != NULL)
			free(r->eom_rdata);
		ctx->ctx_eomreqs = r->eom_next;
		free(r);
	}
}

/*
**  MT_EOM_REQUEST -- record a request received during EOM
**
**  Parameters:
**  	ctx -- mt_context handle
**  	cmd -- command received
**  	len -- length of data
**  	data -- data received (i.e. request parameters)
**
**  Return value:
**  	TRUE iff addition was successful.
*/

_Bool
mt_eom_request(struct mt_context *ctx, char cmd, size_t len, char *data)
{
	struct mt_eom_request *r;

	assert(ctx != NULL);

	r = (struct mt_eom_request *) malloc(sizeof *r);
	if (r == NULL)
		return FALSE;

	r->eom_request = cmd;
	r->eom_rlen = len;
	r->eom_rdata = malloc(len);
	if (r->eom_rdata == NULL)
	{
		free(r);
		return FALSE;
	}
	memcpy(r->eom_rdata, data, len);

	r->eom_next = ctx->ctx_eomreqs;
	ctx->ctx_eomreqs = r;

	return TRUE;
}

/*
**  MT_MILTER_READ -- read from a connected filter
**
**  Parameters:
**  	fd -- descriptor to which to write
**  	cmd -- milter command received (returned)
** 	buf -- where to write data
**  	buflen -- bytes available at "buf" (updated)
** 
**  Return value:
**  	TRUE iff successful.
*/

_Bool
mt_milter_read(int fd, char *cmd, const char *buf, size_t *len)
{
	int i;
	int expl;
	size_t rlen;
	fd_set fds;
	struct timeval timeout;
	char data[MILTER_LEN_BYTES + 1];

	assert(fd >= 0);

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	timeout.tv_sec = tmo;
	timeout.tv_usec = 0;

	i = select(fd + 1, &fds, NULL, NULL, &timeout);
	if (i == 0)
	{
		fprintf(stderr, "%s: select(): timeout on fd %d\n", progname,
		        fd);

		return FALSE;
	}
	else if (i == -1)
	{
		fprintf(stderr, "%s: select(): fd %d: %s\n", progname, fd,
		        strerror(errno));

		return FALSE;
	}

	rlen = read(fd, data, sizeof data);
	if (rlen != sizeof data)
	{
		fprintf(stderr, "%s: read(%d): returned %ld, expected %ld\n",
		        progname, fd, (long) rlen, (long) sizeof data);

		return FALSE;
	}

	*cmd = data[MILTER_LEN_BYTES];
	data[MILTER_LEN_BYTES] = '\0';
	(void) memcpy(&i, data, MILTER_LEN_BYTES);
	expl = ntohl(i) - 1;

	rlen = 0;

	if (expl > 0)
	{
		rlen = read(fd, (void *) buf, expl);
		if (rlen != expl)
		{
			fprintf(stderr,
			        "%s: read(%d): returned %ld, expected %ld\n",
			        progname, fd, (long) rlen, (long) expl);

			return FALSE;
		}
	}

	if (verbose > 1)
	{
		fprintf(stdout, "%s: mt_milter_read(%d): cmd %c, len %ld\n",
		        progname, fd, *cmd, (long) rlen);
	}

	*len = rlen;

	return (expl == rlen);
}

/*
**  MT_MILTER_WRITE -- write to a connected filter
**
**  Parameters:
**  	fd -- descriptor to which to write
**  	cmd -- command to send (an SMFIC_* constant)
**  	buf -- command data (or NULL)
**  	len -- length of data at "buf"
**
**  Return value:
**  	TRUE iff successful.
*/

_Bool
mt_milter_write(int fd, int cmd, const char *buf, size_t len)
{
	char command = (char) cmd;
	ssize_t sl, i;
	int num_vectors;
	uint32_t nl;
	char data[MILTER_LEN_BYTES + 1];
	struct iovec vector[2];

	assert(fd >= 0);

	if (verbose > 1)
	{
		fprintf(stdout, "%s: mt_milter_write(%d): cmd %c, len %ld\n",
		        progname, fd, command, (long) len);
	}

	nl = htonl(len + 1);
	(void) memcpy(data, (char *) &nl, MILTER_LEN_BYTES);
	data[MILTER_LEN_BYTES] = command;
	sl = MILTER_LEN_BYTES + 1;

	/* set up the vector for the size / command */
	vector[0].iov_base = (void *) data;
	vector[0].iov_len  = sl;

	/*
	**  Determine if there is command data.  If so, there will be two
	**  vectors.  If not, there will be only one.  The vectors are set
	**  up here and 'num_vectors' and 'sl' are set appropriately.
	*/

	if (len <= 0 || buf == NULL)
	{
		num_vectors = 1;
	}
	else
	{
		num_vectors = 2;
		sl += len;
		vector[1].iov_base = (void *) buf;
		vector[1].iov_len  = len;
	}

	/* write the vector(s) */
	i = writev(fd, vector, num_vectors);
	if (i != sl)
	{
		fprintf(stderr, "%s: writev(%d): returned %ld, expected %ld\n",
		        progname, fd, (long) i, (long) sl);
	}

	return (i == sl);
}

/*
**  MT_ASSERT_STATE -- bring a connection up to a given state
**
**  Parameters:
**  	ctx -- miltertest context
**  	state -- desired state
**
**  Return value:
**  	TRUE if successful, FALSE otherwise.
*/

_Bool
mt_assert_state(struct mt_context *ctx, int state)
{
	size_t len;
	size_t s;
	uint16_t port;
	char buf[BUFRSZ];

	assert(ctx != NULL);

	if (state >= STATE_NEGOTIATED && ctx->ctx_state < STATE_NEGOTIATED)
	{
		char rcmd;
		size_t buflen;
		uint32_t mta_version;
		uint32_t mta_protoopts;
		uint32_t mta_actions;
		uint32_t nvers;
		uint32_t npopts;
		uint32_t nacts;

		buflen = sizeof buf;

		mta_version = SMFI_PROT_VERSION;
		mta_protoopts = SMFI_CURR_PROT;
		mta_actions = SMFI_CURR_ACTS;

		nvers = htonl(mta_version);
		nacts = htonl(mta_actions);
		npopts = htonl(mta_protoopts);

		(void) memcpy(buf, (char *) &nvers, MILTER_LEN_BYTES);
		(void) memcpy(buf + MILTER_LEN_BYTES,
		              (char *) &nacts, MILTER_LEN_BYTES);
		(void) memcpy(buf + (MILTER_LEN_BYTES * 2),
		              (char *) &npopts, MILTER_LEN_BYTES);

		if (!mt_milter_write(ctx->ctx_fd, SMFIC_OPTNEG, buf,
		                     MILTER_OPTLEN))
			return FALSE;

		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
			return FALSE;

		if (rcmd != SMFIC_OPTNEG)
		{
			if (verbose > 0)
			{
				fprintf(stdout,
				        "%s: filter returned status %d to option negotiation on fd %d\n", 
				        progname, rcmd, ctx->ctx_fd);
			}

			ctx->ctx_state = STATE_DEAD;
			return FALSE;
		}

		/* decode and store requested protocol steps and actions */
		(void) memcpy((char *) &nvers, buf, MILTER_LEN_BYTES);
		(void) memcpy((char *) &nacts, buf + MILTER_LEN_BYTES,
		              MILTER_LEN_BYTES);
		(void) memcpy((char *) &npopts, buf + (MILTER_LEN_BYTES * 2),
		              MILTER_LEN_BYTES);

		ctx->ctx_mactions = ntohl(nacts);
		ctx->ctx_mpopts = ntohl(npopts);

		ctx->ctx_state = STATE_NEGOTIATED;
	}

	if (state >= STATE_CONNINFO && ctx->ctx_state < STATE_CONNINFO)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOCONNECT))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			port = htons(DEFCLIENTPORT);
			len = strlcpy(buf, DEFCLIENTHOST, sizeof buf);
			buf[len++] = '\0';
			buf[len++] = '4';		/* IPv4 only for now */
			memcpy(&buf[len], &port, sizeof port);
			len += sizeof port;
			memcpy(&buf[len], DEFCLIENTIP,
			       strlen(DEFCLIENTIP) + 1);

			s = len + strlen(DEFCLIENTIP) + 1;

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_CONNECT,
			                     buf, s))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_CONN))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to connection information on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_CONNINFO;
	}

	if (state >= STATE_HELO && ctx->ctx_state < STATE_HELO)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOHELO))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			len = strlcpy(buf, DEFCLIENTHOST, sizeof buf);
			buf[len++] = '\0';

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_HELO,
			                     buf, len))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_HELO))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to HELO on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_HELO;
	}

	if (state >= STATE_ENVFROM && ctx->ctx_state < STATE_ENVFROM)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOMAIL))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			len = strlcpy(buf, DEFSENDER, sizeof buf);
			buf[len++] = '\0';

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_MAIL,
			                     buf, len))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_MAIL))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to MAIL on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_ENVFROM;
	}

	if (state >= STATE_ENVRCPT && ctx->ctx_state < STATE_ENVRCPT)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NORCPT))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			len = strlcpy(buf, DEFRECIPIENT, sizeof buf);
			buf[len++] = '\0';

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_RCPT,
			                     buf, len))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if ((ctx->ctx_mpopts & SMFIP_NR_RCPT) == 0)
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to RCPT on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_ENVRCPT;
	}

	if (state >= STATE_DATA && ctx->ctx_state < STATE_DATA)
	{
#ifdef SMFIC_DATA
		if (!CHECK_MPOPTS(ctx, SMFIP_NODATA))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_DATA, NULL, 0))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_DATA))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to DATA on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}
#endif /* SMFIC_DATA */

		ctx->ctx_state = STATE_DATA;
	}

	if (state >= STATE_HEADER && ctx->ctx_state < STATE_HEADER)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOHDRS))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			len = strlcpy(buf, DEFHEADERNAME, sizeof buf);
			buf[len++] = '\0';
			len += strlcpy(buf + len, DEFSENDER, sizeof buf - len);
			buf[len++] = '\0';

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_HEADER,
			                     buf, len))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_HDR))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to header on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}

				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_HEADER;
	}

	if (state >= STATE_EOH && ctx->ctx_state < STATE_EOH)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOEOH))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_EOH, NULL, 0))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_EOH))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to EOH on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}
	
				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_EOH;
	}

	if (state >= STATE_BODY && ctx->ctx_state < STATE_BODY)
	{
		if (!CHECK_MPOPTS(ctx, SMFIP_NOBODY))
		{
			char rcmd;
			size_t buflen;

			buflen = sizeof buf;

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_BODY, DEFBODY,
			                     strlen(DEFBODY)))
				return FALSE;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_BODY))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd,
				                    buf, &buflen))
					return FALSE;

				ctx->ctx_response = rcmd;
			}

			if (rcmd != SMFIR_CONTINUE)
			{
				if (verbose > 0)
				{
					fprintf(stdout,
					        "%s: filter returned status %d to body on fd %d\n", 
					        progname, rcmd, ctx->ctx_fd);
				}
	
				ctx->ctx_state = STATE_DEAD;
			}
		}

		ctx->ctx_state = STATE_BODY;
	}

	return TRUE;
}

/*
**  MT_ECHO -- echo a string
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_echo(lua_State *l)
{
	char *str;

	assert(l != NULL);

	if (lua_gettop(l) != 1 || !lua_isstring(l, 1))
	{
		lua_pushstring(l, "mt.echo(): Invalid argument");
		lua_error(l);
	}

	str = (char *) lua_tostring(l, 1);
	lua_pop(l, 1);

	fprintf(stdout, "%s\n", str);

	return 0;
}

/*
**  MT_CHDIR -- change working directory
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_chdir(lua_State *l)
{
	char *str;

	assert(l != NULL);

	if (lua_gettop(l) != 1 || !lua_isstring(l, 1))
	{
		lua_pushstring(l, "mt.chdir(): Invalid argument");
		lua_error(l);
	}

	str = (char *) lua_tostring(l, 1);
	lua_pop(l, 1);

	if (chdir(str) != 0)
	{
		lua_pushfstring(l, "mt.chdir(): %s: %s", str, strerror(errno));
		lua_error(l);
	}

	if (verbose > 1)
		fprintf(stderr, "%s: now in directory %s\n", progname, str);

	return 0;
}

/*
**  MT_GETCWD -- get current working directory
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	String containing current working directory.
*/

int
mt_getcwd(lua_State *l)
{
	char dir[MAXPATHLEN + 1];

	assert(l != NULL);

	if (lua_gettop(l) != 0)
	{
		lua_pushstring(l, "mt.getcwd(): Invalid argument");
		lua_error(l);
	}

	memset(dir, '\0', sizeof dir);

	if (getcwd(dir, MAXPATHLEN) == NULL)
	{
		lua_pushstring(l, "mt.getcwd(): getcwd() returned error");
		lua_error(l);
	}

	lua_pushstring(l, dir);

	return 1;
}

/*
**  MT_SET_TIMEOUT -- set read timeout
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_set_timeout(lua_State *l)
{
	assert(l != NULL);

	if (lua_gettop(l) != 1 || !lua_isnumber(l, 1))
	{
		lua_pushstring(l, "mt.set_timeout(): Invalid argument");
		lua_error(l);
	}

	tmo = (unsigned int) lua_tonumber(l, 1);
	lua_pop(l, 1);

	return 0;
}

/*
**  MT_STARTFILTER -- start a filter
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_startfilter(lua_State *l)
{
	const char **argv;
	int c;
	int status;
	int args;
	int fds[2];
	pid_t child;

	assert(l != NULL);

	args = lua_gettop(l);
	if (args < 1)
	{
		lua_pushstring(l, "mt.startfilter(): Invalid argument");
		lua_error(l);
	}

	for (c = 1; c <= args; c++)
	{
		if (!lua_isstring(l, c))
		{
			lua_pushstring(l,
			               "mt.startfilter(): Invalid argument");
			lua_error(l);
		}
	}

	argv = (const char **) malloc(sizeof(char *) * (args + 1));
	if (argv == NULL)
	{
		lua_pushfstring(l, "mt.startfilter(): malloc(): %s",
		                strerror(errno));
		lua_error(l);
	}

	for (c = 1; c <= args; c++)
	{
		argv[c - 1] = lua_tostring(l, c);
		if (verbose > 2)
		{
			fprintf(stderr, "%s: argv[%d] = `%s'\n", progname, c - 1,
			        argv[c - 1]);
		}
	}
	argv[c - 1] = NULL;
	lua_pop(l, c);

	if (pipe(fds) != 0)
	{
		lua_pushfstring(l, "mt.startfilter(): pipe(): %s",
		                strerror(errno));
		lua_error(l);
	}

	if (fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0)
	{
		lua_pushfstring(l, "mt.startfilter(): fcntl(): %s",
		                strerror(errno));
		lua_error(l);
	}

	child = fork();
	switch (child)
	{
	  case -1:
		lua_pushfstring(l, "mt.startfilter(): fork(): %s",
		                strerror(errno));
		lua_error(l);

	  case 0:
		close(fds[0]);
		execv(argv[0], (char * const *) argv);
		exit(1);

	  default:
		close(fds[1]);

		c = read(fds[0], &args, sizeof(args));
		if (c == -1)
		{
			lua_pushfstring(l, "mt.startfilter(): read(): %s",
			                strerror(errno));
			lua_error(l);
		}
		else if (c != 0)
		{
			lua_pushfstring(l,
			                "mt.startfilter(): read(): got %d, expecting 0",
			                c);
			lua_error(l);
		}

		close(fds[0]);

		filterpid = child;

		child = wait4(filterpid, &status, WNOHANG, NULL);
		if (child != 0)
		{
			lua_pushfstring(l,
			                "mt.startfilter(): wait4(): child %d exited prematurely, status %d",
			                child, status);
			lua_error(l);
		}

		if (verbose > 0)
		{
			fprintf(stderr, "%s: '%s' started in process %d\n",
			        progname, argv[0], filterpid);
		}

		free((void *) argv);

		break;
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_SIGNAL -- signal a filter
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_signal(lua_State *l)
{
	int signum;

	assert(l != NULL);

	if (lua_gettop(l) != 1 || !lua_isnumber(l, 1))
	{
		lua_pushstring(l, "mt.signal(): Invalid argument");
		lua_error(l);
	}

	signum = lua_tonumber(l, 1);
	lua_pop(l, 1);

	if (filterpid <= 1)
	{
		lua_pushstring(l, "mt.signal(): Filter not running");
		lua_error(l);
	}

	if (kill(filterpid, signum) != 0)
	{
		lua_pushfstring(l, "mt.signal(): kill(): %s", strerror(errno));
		lua_error(l);
	}

	if (verbose > 0)
		fprintf(stderr, "%s: sent signal %d\n", progname, signum);

	lua_pushnil(l);

	return 1;
}

/*
**  MT_CONNECT -- connect to a filter, returning a handle
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	A new connection handle (on the Lua stack).
*/

int
mt_connect(lua_State *l)
{
	int top;
	int af;
	int fd = -1;
	int saverr = 0;
	u_int count = 1;
	useconds_t interval = 0;
	char *at;
	char *p;
	const char *sockinfo;
	struct mt_context *new;

	assert(l != NULL);

	top = lua_gettop(l);

	if (!(top == 1 && lua_isstring(l, 1)) &&
	    !(top == 3 && lua_isstring(l, 1) && lua_isnumber(l, 2) &&
	                  lua_isnumber(l, 3)))
	{
		lua_pushstring(l, "mt.connect(): Invalid argument");
		lua_error(l);
	}

	sockinfo = lua_tostring(l, 1);
	if (top == 3)
	{
		char *f;

		count = (u_int) lua_tonumber(l, 2);
		interval = (useconds_t) (1000000. * lua_tonumber(l, 3));

		f = getenv("MILTERTEST_RETRY_SPEED_FACTOR");
		if (f != NULL)
		{
			unsigned int factor;

			factor = strtoul(f, &p, 10);
			if (*p == '\0')
				interval *= factor;
		}
	}
	lua_pop(l, top);

	af = AF_UNSPEC;
	p = strchr(sockinfo, ':');
	if (p == NULL)
	{
		af = AF_UNIX;
	}
	else
	{
		*p = '\0';
		if (strcasecmp(sockinfo, "inet") == 0)
			af = AF_INET;
		else if (strcasecmp(sockinfo, "unix") == 0 ||
		         strcasecmp(sockinfo, "local") == 0)
			af = AF_UNIX;
		*p = ':';
	}

	if (af == AF_UNSPEC)
	{
		lua_pushstring(l, "mt.connect(): Invalid argument");
		lua_error(l);
	}

	switch (af)
	{
	  case AF_UNIX:
	  {
		struct sockaddr_un sa;

		memset(&sa, '\0', sizeof sa);
		sa.sun_family = AF_UNIX;
#ifdef HAVE_SUN_LEN
		sa.sun_len = sizeof sa;
#endif /* HAVE_SUN_LEN */
		if (p == NULL)
			strlcpy(sa.sun_path, sockinfo, sizeof sa.sun_path);
		else
			strlcpy(sa.sun_path, p + 1, sizeof sa.sun_path);

		while (count > 0)
		{
			fd = socket(PF_UNIX, SOCK_STREAM, 0);
			if (fd < 0)
			{
				lua_pushfstring(l, "mt.connect(): socket(): %s",
				                strerror(errno));
				lua_error(l);
			}

			saverr = 0;

			if (connect(fd, (struct sockaddr *) &sa,
			            sizeof sa) == 0)
				break;

			saverr = errno;

			if (verbose > 1)
			{
				fprintf(stdout,
				        "%s: connect(): %s; %u tr%s left\n",
				        progname, strerror(errno), count - 1,
				        count == 2 ? "y" : "ies");
			}

			close(fd);

			usleep(interval);

			count--;
		}

		if (saverr != 0)
		{
			lua_pushfstring(l, "mt.connect(): %s: connect(): %s",
			                sockinfo, strerror(errno));
			lua_error(l);
		}

		break;
	  }

	  case AF_INET:
	  {
		struct servent *srv;
		struct sockaddr_in sa;

		memset(&sa, '\0', sizeof sa);
		sa.sin_family = AF_INET;

		p++;

		at = strchr(p, '@');
		if (at == NULL)
		{
			sa.sin_addr.s_addr = INADDR_ANY;
		}
		else
		{
			struct hostent *h;

			*at = '\0';

			h = gethostbyname(at + 1);
			if (h != NULL)
			{
				memcpy(&sa.sin_addr.s_addr, h->h_addr,
				       sizeof sa.sin_addr.s_addr);
			}
			else
			{
				sa.sin_addr.s_addr = inet_addr(at + 1);
			}
		}

		srv = getservbyname(p, "tcp");
		if (srv != NULL)
		{
			sa.sin_port = srv->s_port;
		}
		else
		{
			int port;
			char *q;

			port = strtoul(p, &q, 10);
			if (*q != '\0')
			{
				lua_pushstring(l,
				               "mt.connect(): Invalid argument");
				lua_error(l);
			}

			sa.sin_port = htons(port);
		}

		if (at != NULL)
			*at = '@';

		while (count > 0)
		{
			fd = socket(PF_INET, SOCK_STREAM, 0);
			if (fd < 0)
			{
				lua_pushfstring(l, "mt.connect(): socket(): %s",
				                strerror(errno));
				lua_error(l);
			}

			saverr = 0;

			if (connect(fd, (struct sockaddr *) &sa,
			            sizeof sa) == 0)
				break;

			saverr = errno;

			if (verbose > 1)
			{
				fprintf(stdout,
				        "%s: connect(): %s; %u tr%s left\n",
				        progname, strerror(errno), count - 1,
				        count == 2 ? "y" : "ies");
			}

			close(fd);

			usleep(interval);

			count--;
		}

		if (saverr != 0)
		{
			lua_pushfstring(l, "mt.connect(): %s: connect(): %s",
			                sockinfo, strerror(errno));
			lua_error(l);
		}

		break;
	  }

	  default:
		assert(0);
	}

	new = (struct mt_context *) malloc(sizeof *new);
	if (new == NULL)
	{
		lua_pushfstring(l, "mt.connect(): malloc(): %s",
		                strerror(errno));
		lua_error(l);
	}

	new->ctx_state = STATE_INIT;
	new->ctx_fd = fd;
	new->ctx_response = '\0';
	new->ctx_eomreqs = NULL;
	new->ctx_mactions = 0;
	new->ctx_mpopts = 0;

	lua_pushlightuserdata(l, new);

	if (verbose > 0)
	{
		fprintf(stdout, "%s: connected to '%s', fd %d\n",
		        progname, sockinfo, fd);
	}

	return 1;
}

/*
**  MT_SLEEP -- sleep
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_sleep(lua_State *l)
{
	double p;
	useconds_t usecs;

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_isnumber(l, 1))
	{
		lua_pushstring(l, "mt.sleep(): Invalid argument");
		lua_error(l);
	}

	p = lua_tonumber(l, 1);
	usecs = (useconds_t) (1000000. * p);
	lua_pop(l, 1);

	if (verbose > 1)
	{
		fprintf(stdout, "%s: pausing for %f second%s\n",
		        progname, p, usecs == 1000000 ? "" : "s");
	}

	usleep(usecs);

	lua_pushnil(l);

	return 1;
}

/*
**  MT_DISCONNECT -- disconnect from a filter
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_disconnect(lua_State *l)
{
	_Bool polite = TRUE;
	int top;
	
	struct mt_context *ctx;

	assert(l != NULL);

	top = lua_gettop(l);
	if ((top != 1 && top != 2) ||
	    !lua_islightuserdata(l, 1) ||
	    (top == 2 && !lua_isboolean(l, 2)))
	{
		lua_pushstring(l, "mt.disconnect(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	if (top == 2)
		polite = lua_toboolean(l, 2);
	lua_pop(l, top);

	if (polite)
		(void) mt_milter_write(ctx->ctx_fd, SMFIC_QUIT, NULL, 0);

	(void) close(ctx->ctx_fd);

	if (verbose > 0)
	{
		fprintf(stdout, "%s: disconnected fd %d\n",
		        progname, ctx->ctx_fd);
	}

	free(ctx);

	lua_pushnil(l);

	return 1;
}

/*
**  MT_TEST_ACTION -- send an action bit
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	Boolean (true/false)
*/

int
mt_test_action(lua_State *l)
{
	struct mt_context *ctx;
	unsigned long action;

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isnumber(l, 2))
	{
		lua_pushstring(l, "mt.test_action(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	action = lua_tonumber(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_NEGOTIATED))
		lua_error(l);

	lua_pushboolean(l, (ctx->ctx_mactions & action) != 0);

	return 1;
}

/*
**  MT_TEST_OPTION -- send a protocol option bit
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	Boolean (true/false)
*/

int
mt_test_option(lua_State *l)
{
	unsigned long option;
	struct mt_context *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isnumber(l, 2))
	{
		lua_pushstring(l, "mt.test_option(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	option = lua_tonumber(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_NEGOTIATED))
		lua_error(l);

	lua_pushboolean(l, (ctx->ctx_mpopts & option) != 0);

	return 1;
}

/*
**  MT_NEGOTIATE -- option negotiation
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_negotiate(lua_State *l)
{
	char rcmd;
	size_t buflen;
	uint32_t mta_version;
	uint32_t mta_protoopts;
	uint32_t mta_actions;
	uint32_t nvers;
	uint32_t npopts;
	uint32_t nacts;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	if (lua_gettop(l) != 4 ||
	    !lua_islightuserdata(l, 1) ||
	    (!lua_isnil(l, 2) && !lua_isnumber(l, 2)) ||
	    (!lua_isnil(l, 3) && !lua_isnumber(l, 3)) ||
	    (!lua_isnil(l, 4) && !lua_isnumber(l, 4)))
	{
		lua_pushstring(l, "mt.negotiate(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);

	buflen = sizeof buf;

	if (lua_isnumber(l, 2))
		mta_version = lua_tonumber(l, 2);
	else
		mta_version = SMFI_PROT_VERSION;

	if (lua_isnumber(l, 3))
		mta_protoopts = lua_tonumber(l, 3);
	else
		mta_protoopts = SMFI_CURR_PROT;

	if (lua_isnumber(l, 4))
		mta_actions = lua_tonumber(l, 4);
	else
		mta_actions = SMFI_CURR_ACTS;

	lua_pop(l, lua_gettop(l));

	nvers = htonl(mta_version);
	nacts = htonl(mta_actions);
	npopts = htonl(mta_protoopts);

	(void) memcpy(buf, (char *) &nvers, MILTER_LEN_BYTES);
	(void) memcpy(buf + MILTER_LEN_BYTES,
	              (char *) &nacts, MILTER_LEN_BYTES);
	(void) memcpy(buf + (MILTER_LEN_BYTES * 2),
	              (char *) &npopts, MILTER_LEN_BYTES);

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_OPTNEG, buf, MILTER_OPTLEN))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
	{
		lua_pushstring(l, "mt.milter_read() failed");
		return 1;
	}

	if (rcmd != SMFIC_OPTNEG)
	{
		if (verbose > 0)
		{
			fprintf(stdout,
			        "%s: filter returned status %d to option negotiation on fd %d\n", 
			        progname, rcmd, ctx->ctx_fd);
		}

		ctx->ctx_state = STATE_DEAD;

		lua_pushnil(l);
		return 1;
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_NEGOTIATED;

	/* decode and store requested protocol steps and actions */
	(void) memcpy((char *) &nvers, buf, MILTER_LEN_BYTES);
	(void) memcpy((char *) &nacts, buf + MILTER_LEN_BYTES,
	              MILTER_LEN_BYTES);
	(void) memcpy((char *) &npopts, buf + (MILTER_LEN_BYTES * 2),
	              MILTER_LEN_BYTES);

	ctx->ctx_mactions = ntohl(nacts);
	ctx->ctx_mpopts = ntohl(npopts);

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: option negotiation sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);
	return 1;
}

/*
**  MT_MACRO -- send a macro
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_macro(lua_State *l)
{
	int type;
	int top;
	int n = 0;
	int c;
	size_t s;
	struct mt_context *ctx;
	char *bp;
	char *name;
	char *value;
	char buf[BUFRSZ];

	assert(l != NULL);

	top = lua_gettop(l);

	if (top < 4 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isnumber(l, 2) ||
	    !lua_isstring(l, 3) ||
	    !lua_isstring(l, 4))
	{
		lua_pushstring(l, "mt.macro(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	type = lua_tonumber(l, 2);

	if (!mt_assert_state(ctx, STATE_NEGOTIATED))
		lua_error(l);

	s = 1;
	buf[0] = type;
	bp = buf + 1;

	for (c = 3; c < top; c += 2)
	{
		if (c + 1 > top ||
		    !lua_isstring(l, c) ||
		    !lua_isstring(l, c + 1))
		{
			lua_pop(l, top);
			lua_pushstring(l, "mt.macro(): Invalid argument");
			lua_error(l);
		}

		name = (char *) lua_tostring(l, c);
		value = (char *) lua_tostring(l, c + 1);

		if (strlen(name) + strlen(value) + 2 + bp > buf + sizeof buf)
		{
			lua_pop(l, top);
			lua_pushstring(l, "mt.macro(): Buffer overflow");
			lua_error(l);
		}

		memcpy(bp, name, strlen(name) + 1);
		bp += strlen(name) + 1;
		memcpy(bp, value, strlen(value) + 1);
		bp += strlen(value) + 1;
 		s += strlen(name) + 1 + strlen(value) + 1;
		n++;
	}

	lua_pop(l, top);

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_MACRO, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	if (verbose > 0)
	{
		fprintf(stdout, "%s: %d '%c' macro(s) sent on fd %d\n",
		        progname, n, type, ctx->ctx_fd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_CONNINFO -- send connection information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_conninfo(lua_State *l)
{
	char rcmd;
	char family = 'U';
	size_t buflen;
	size_t s;
	uint16_t port;
	struct mt_context *ctx;
	char *host;
	char *bp;
	char *ipstr;
	char buf[BUFRSZ];
	char tmp[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 3 ||
	    !lua_islightuserdata(l, 1) ||
	    (!lua_isnil(l, 2) && !lua_isstring(l, 2)) ||
	    (!lua_isnil(l, 3) && !lua_isstring(l, 3)))
	{
		lua_pushstring(l, "mt.conninfo(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	if (lua_isstring(l, 2))
		host = (char *) lua_tostring(l, 2);
	else
		host = DEFCLIENTHOST;
	if (lua_isstring(l, 3))
		ipstr = (char *) lua_tostring(l, 3);
	else
		ipstr = NULL;

	lua_pop(l, 3);

	if (!mt_assert_state(ctx, STATE_NEGOTIATED))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOCONNECT))
	{
		lua_pushstring(l, "mt.conninfo(): negotiated SMFIP_NOCONNECT");
		lua_error(l);
	}

	if (ipstr == NULL)
	{
#if (HAVE_GETADDRINFO && HAVE_INET_NTOP)
		char *a = NULL;
		struct addrinfo *res;
		struct sockaddr_in *s4;
		struct sockaddr_in6 *s6;

		if (getaddrinfo(host, NULL, NULL, &res) != 0)
		{
			lua_pushfstring(l, "mt.conninfo(): host '%s' unknown",
			                host);
			lua_error(l);
		}

		if (res->ai_family == AF_INET)
		{
			s4 = (struct sockaddr_in *) res->ai_addr;
			a = (char *) &s4->sin_addr;
			family = '4';
		}
		else if (res->ai_family == AF_INET6)
		{
			s6 = (struct sockaddr_in6 *) res->ai_addr;
			a = (char *) &s6->sin6_addr;
			family = '6';
		}

		if (family != 'U')
		{
			memset(tmp, '\0', sizeof tmp);

			if (inet_ntop(res->ai_family, a,
			              tmp, sizeof tmp - 1) == NULL)
			{
				freeaddrinfo(res);
				lua_pushfstring(l,
				                "mt.conninfo(): can't convert address for host '%s' to text",
				                host);
				lua_error(l);
			}
		}

		freeaddrinfo(res);
		ipstr = tmp;
#else /* HAVE_GETADDRINFO && HAVE_INET_NTOP */
		struct hostent *h;
		struct in_addr sa;

		h = gethostbyname(host);
		if (h == NULL)
		{
			lua_pushfstring(l, "mt.conninfo(): host '%s' unknown",
			                host);
			lua_error(l);
		}

		memcpy(&sa.s_addr, h->h_addr, sizeof sa.s_addr);
		mt_inet_ntoa(sa, tmp, sizeof tmp);
		ipstr = tmp;
		family = '4';
#endif /* HAVE_GETADDRINFO && HAVE_INET_NTOP */
	}
	else if (strcasecmp(ipstr, "unspec") != 0)
	{
#ifdef HAVE_INET_PTON
		struct in_addr a;
		struct in6_addr a6;

		if (inet_pton(AF_INET6, ipstr, &a6.s6_addr) == 1)
		{
			family = '6';
		}
		else if (inet_pton(AF_INET, ipstr, &a.s_addr) == 1)
		{
			family = '4';
		}
		else
		{
			lua_pushfstring(l,
			                "mt.conninfo(): invalid IP address '%s'",
			                ipstr);
			lua_error(l);
		}
#else /* HAVE_INET_PTON */
		struct in_addr sa;

		sa.s_addr = inet_addr(ipstr);
		if (sa.s_addr == INADDR_NONE)
		{
			lua_pushfstring(l,
			                "mt.conninfo(): invalid IPv4 address '%s'",
			                ipstr);
			lua_error(l);
		}
		family = '4';
#endif /* HAVE_INET_PTON */
	}

	bp = buf;
	memcpy(bp, host, strlen(host));
	bp += strlen(host);
	*bp++ = '\0';
	memcpy(bp, &family, sizeof family);
	bp += sizeof family;

	s = strlen(host) + 1 + sizeof(char);

	if (family != 'U')			/* known family data */
	{
		port = htons(DEFCLIENTPORT);	/* don't really need this */

		memcpy(bp, &port, sizeof port);
		bp += sizeof port;
		memcpy(bp, ipstr, strlen(ipstr) + 1);

		s += sizeof port + strlen(ipstr) + 1;
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_CONNECT, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_CONN))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_CONNINFO;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: connection details sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_UNKNOWN -- send unknown command information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_unknown(lua_State *l)
{
#ifdef SMFIC_UNKNOWN
	char rcmd;
	size_t buflen;
	size_t s;
	struct mt_context *ctx;
	char *cmd;
	char *bp;
	char buf[BUFRSZ];
#endif /* SMFIC_UNKNOWN */

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2))
	{
		lua_pushstring(l, "mt.unknown(): Invalid argument");
		lua_error(l);
	}

#ifndef SMFIC_UNKNOWN
	lua_pushstring(l, "mt.unknown(): Operation not supported");
	lua_error(l);
#else /* ! SMFIC_UNKNOWN */
	ctx = (struct mt_context *) lua_touserdata(l, 1);
	cmd = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_CONNINFO))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOUNKNOWN))
	{
		lua_pushstring(l, "mt.unknown(): negotiated SMFIP_NOUNKNOWN");
		lua_error(l);
	}

	s = strlen(cmd) + 1;

	bp = buf;
	memcpy(bp, cmd, strlen(cmd));
	bp += strlen(cmd);
	*bp++ = '\0';

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_UNKNOWN, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_UNKN))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: UNKNOWN sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);
#endif /* ! SMFIC_UNKNOWN */

	return 1;
}

/*
**  MT_HELO -- send HELO information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_helo(lua_State *l)
{
	char rcmd;
	size_t buflen;
	size_t s;
	struct mt_context *ctx;
	char *host;
	char *bp;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2))
	{
		lua_pushstring(l, "mt.helo(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	host = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_CONNINFO))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOHELO))
	{
		lua_pushstring(l, "mt.helo(): negotiated SMFIP_NOHELO");
		lua_error(l);
	}

	s = strlen(host) + 1;

	bp = buf;
	memcpy(bp, host, strlen(host));
	bp += strlen(host);
	*bp++ = '\0';

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_HELO, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_HELO))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_HELO;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: HELO sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_MAILFROM -- send MAIL FROM information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_mailfrom(lua_State *l)
{
	char rcmd;
	int c;
	size_t buflen;
	size_t s;
	char *p;
	char *bp;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) < 2 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.mailfrom(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);

	s = 0;
	bp = buf;

	for (c = 2; c <= lua_gettop(l); c++)
	{
		p = (char *) lua_tostring(l, c);

		s += strlen(p) + 1;

		memcpy(bp, p, strlen(p) + 1);

		bp += strlen(p) + 1;

		/* XXX -- watch for overruns */
	}

	lua_pop(l, lua_gettop(l));

	if (!mt_assert_state(ctx, STATE_HELO))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOMAIL))
	{
		lua_pushstring(l, "mt.mailfrom(): negotiated SMFIP_NOMAIL");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_MAIL, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_MAIL))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_ENVFROM;
	mt_flush_eomreqs(ctx);

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: MAIL sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_RCPTTO -- send RCPT TO information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_rcptto(lua_State *l)
{
	char rcmd;
	int c;
	size_t buflen;
	size_t s;
	char *p;
	char *bp;
	char *end;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) < 2 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.rcptto(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);

	s = 0;
	bp = buf;
	end = bp + sizeof buf;
	memset(buf, '\0', sizeof buf);

	for (c = 2; c <= lua_gettop(l); c++)
	{
		p = (char *) lua_tostring(l, c);

		s += strlen(p) + 1;

		if (bp + strlen(p) >= end)
		{
			lua_pushstring(l, "mt.rcptto(): Input overflow");
			lua_error(l);
		}

		memcpy(bp, p, strlen(p) + 1);

		bp += strlen(p) + 1;
	}

	lua_pop(l, lua_gettop(l));

	if (!mt_assert_state(ctx, STATE_ENVFROM))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NORCPT))
	{
		lua_pushstring(l, "mt.rcptto(): negotiated SMFIP_NORCPT");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_RCPT, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_RCPT))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_ENVRCPT;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: RCPT sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_DATA -- send DATA notice
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_data(lua_State *l)
{
#ifdef SMFIC_DATA
	char rcmd;
	size_t buflen;
	struct mt_context *ctx;
	char buf[BUFRSZ];
#endif /* SMFIC_DATA */

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.data(): Invalid argument");
		lua_error(l);
	}

#ifndef SMFIC_DATA
	lua_pushstring(l, "mt.ata(): Operation not supported");
	lua_error(l);
#else /* ! SMFIC_DATA */
	ctx = (struct mt_context *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (!mt_assert_state(ctx, STATE_DATA))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NODATA))
	{
		lua_pushstring(l, "mt.data(): negotiated SMFIP_NODATA");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_DATA, NULL, 0))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_DATA))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_DATA;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: DATA sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);
#endif /* ! SMFIC_DATA */

	return 1;
}

/*
**  MT_HEADER -- send header field information
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_header(lua_State *l)
{
	char rcmd;
	size_t buflen;
	size_t s;
	char *bp;
	char *name;
	char *value;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 3 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2) ||
	    !lua_isstring(l, 3))
	{
		lua_pushstring(l, "mt.header(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	value = (char *) lua_tostring(l, 3);
	lua_pop(l, 3);

	s = strlen(name) + 1 + strlen(value) + 1;
#ifdef SMFIP_HDR_LEADSPC
	if (CHECK_MPOPTS(ctx, SMFIP_HDR_LEADSPC))
		s++;
#endif /* SMFIP_HDR_LEADSPC */

	bp = buf;
	memcpy(buf, name, strlen(name) + 1);
	bp += strlen(name) + 1;
#ifdef SMFIP_HDR_LEADSPC
	if (CHECK_MPOPTS(ctx, SMFIP_HDR_LEADSPC))
		*bp++ = ' ';
#endif /* SMFIP_HDR_LEADSPC */
	memcpy(bp, value, strlen(value) + 1);

	if (!mt_assert_state(ctx, STATE_ENVRCPT))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOHDRS))
	{
		lua_pushstring(l, "mt.header(): negotiated SMFIP_NOHDRS");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_HEADER, buf, s))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_HDR))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_HEADER;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: header sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_EOH -- send end-of-header notice
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_eoh(lua_State *l)
{
	char rcmd;
	size_t buflen;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.eoh(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (!mt_assert_state(ctx, STATE_HEADER))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOEOH))
	{
		lua_pushstring(l, "mt.eoh(): negotiated SMFIP_NOEOH");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_EOH, NULL, 0))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_EOH))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_EOH;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: EOH sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_BODYSTRING -- send a string of body
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_bodystring(lua_State *l)
{
	char rcmd;
	size_t buflen;
	struct mt_context *ctx;
	char *str;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2))
	{
		lua_pushstring(l, "mt.bodystring(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	str = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_EOH))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOBODY))
	{
		lua_pushstring(l, "mt.bodystring(): negotiated SMFIP_NOBODY");
		lua_error(l);
	}

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_BODY, str, strlen(str)))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	buflen = sizeof buf;

	rcmd = SMFIR_CONTINUE;

	if (!CHECK_MPOPTS(ctx, SMFIP_NR_BODY))
	{
		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_BODY;

	if (verbose > 0)
	{
		fprintf(stdout,
		        "%s: %zu byte(s) of body sent on fd %d, reply '%c'\n",
		        progname, strlen(str), ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_BODYRANDOM -- send a random chunk of body
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_bodyrandom(lua_State *l)
{
	char rcmd;
	unsigned long rw;
	unsigned long rl;
	int c;
	size_t buflen;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isnumber(l, 2))
	{
		lua_pushstring(l, "mt.bodyrandom(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	rw = (unsigned long) lua_tonumber(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_EOH))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOBODY))
	{
		lua_pushstring(l, "mt.bodyrandom(): negotiated SMFIP_NOBODY");
		lua_error(l);
	}

	while (rw > 0)
	{
		memset(buf, '\0', sizeof buf);

		rl = random() % (sizeof buf - 3);
		if (rl > rw)
			rl = rw;

		for (c = 0; c < rl; c++)
			buf[c] = (random() % 95) + 32;
		strlcat(buf, "\r\n", sizeof buf);

		if (!mt_milter_write(ctx->ctx_fd, SMFIC_BODY, buf,
		                     strlen(buf)))
		{
			lua_pushstring(l, "mt.milter_write() failed");
			return 1;
		}

		buflen = sizeof buf;

		rcmd = SMFIR_CONTINUE;

		if (!CHECK_MPOPTS(ctx, SMFIP_NR_BODY))
		{
			if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
			{
				lua_pushstring(l, "mt.milter_read() failed");
				return 1;
			}
		}

		ctx->ctx_response = rcmd;
		ctx->ctx_state = STATE_BODY;

		if (verbose > 0)
		{
			fprintf(stdout,
			        "%s: %zu byte(s) of body sent on fd %d, reply '%c'\n",
			        progname, strlen(buf), ctx->ctx_fd, rcmd);
		}

		if (rcmd != SMFIR_CONTINUE)
			break;

		rw -= rl;
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_BODYFILE -- send contents of a file as body
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_bodyfile(lua_State *l)
{
	char rcmd;
	char *file;
	FILE *f;
	ssize_t rlen;
	struct mt_context *ctx;
	char chunk[CHUNKSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 2 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2))
	{
		lua_pushstring(l, "mt.bodyfile(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	file = (char *) lua_tostring(l, 2);
	lua_pop(l, 2);

	if (!mt_assert_state(ctx, STATE_EOH))
		lua_error(l);

	if (CHECK_MPOPTS(ctx, SMFIP_NOBODY))
	{
		lua_pushstring(l, "mt.bodyfile(): negotiated SMFIP_NOBODY");
		lua_error(l);
	}

	f = fopen(file, "r");
	if (f == NULL)
	{
		lua_pushfstring(l, "mt.bodyfile(): %s: fopen(): %s",
		                file, strerror(errno));
		lua_error(l);
	}

	for (;;)
	{
		rlen =  fread(chunk, 1, sizeof chunk, f);

		if (rlen > 0)
		{
			size_t buflen;

			if (!mt_milter_write(ctx->ctx_fd, SMFIC_BODY, chunk,
			                     rlen))
			{
				fclose(f);
				lua_pushstring(l, "mt.milter_write() failed");
				return 1;
			}

			buflen = sizeof chunk;

			rcmd = SMFIR_CONTINUE;

			if (!CHECK_MPOPTS(ctx, SMFIP_NR_BODY))
			{
				if (!mt_milter_read(ctx->ctx_fd, &rcmd, chunk,
				                    &buflen))
				{
					fclose(f);
					lua_pushstring(l,
					               "mt.milter_read() failed");
					return 1;
				}
			}

			if (verbose > 0)
			{
				fprintf(stdout,
				        "%s: %zu byte(s) of body sent on fd %d, reply '%c'\n",
				        progname, rlen, ctx->ctx_fd, rcmd);
			}
		}

		if (rlen < sizeof chunk || rcmd != SMFIR_CONTINUE)
			break;
	}

	fclose(f);

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_BODY;

	lua_pushnil(l);

	return 1;
}

/*
**  MT_EOM -- send end-of-message notice, collect requests
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_eom(lua_State *l)
{
	char rcmd;
	size_t buflen;
	struct mt_context *ctx;
	char buf[BUFRSZ];

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.eom(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (!mt_assert_state(ctx, STATE_BODY))
		lua_error(l);

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_BODYEOB, NULL, 0))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	rcmd = '\0';

	for (;;)
	{
		buflen = sizeof buf;

		if (!mt_milter_read(ctx->ctx_fd, &rcmd, buf, &buflen))
		{
			lua_pushstring(l, "mt.milter_read() failed");
			return 1;
		}

		if (rcmd == SMFIR_CONTINUE ||
		    rcmd == SMFIR_ACCEPT ||
		    rcmd == SMFIR_REJECT ||
		    rcmd == SMFIR_TEMPFAIL ||
		    rcmd == SMFIR_DISCARD)
			break;

		if (!mt_eom_request(ctx, rcmd, buflen,
		                    buflen == 0 ? NULL : buf))
		{
			lua_pushstring(l, "mt.eom_request() failed");
			return 1;
		}

		if (rcmd == SMFIR_REPLYCODE)
			break;
	}

	ctx->ctx_response = rcmd;
	ctx->ctx_state = STATE_EOM;

	if (verbose > 0)
	{
		fprintf(stdout, "%s: EOM sent on fd %d, reply '%c'\n",
		        progname, ctx->ctx_fd, rcmd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_EOM_CHECK -- test for a specific end-of-message action
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_eom_check(lua_State *l)
{
	int op;
	struct mt_context *ctx;
	struct mt_eom_request *r;

	assert(l != NULL);

	if (lua_gettop(l) < 2 || lua_gettop(l) > 5 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isnumber(l, 2))
	{
		lua_pushstring(l, "mt.eom_check(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	op = lua_tonumber(l, 2);

	switch (op)
	{
	  case MT_HDRADD:
	  {
		char *name = NULL;
		char *value = NULL;

		if (lua_gettop(l) >= 3)
		{
			if (!lua_isstring(l, 3))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			name = (char *) lua_tostring(l, 3);
		}

		if (lua_gettop(l) == 4)
		{
			if (!lua_isstring(l, 4))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			value = (char *) lua_tostring(l, 4);
		}

		if (lua_gettop(l) == 5)
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_ADDHEADER)
			{
				char *rname;
				char *rvalue;

				rname = r->eom_rdata;
				rvalue = r->eom_rdata + strlen(rname) + 1;

				if ((name == NULL ||
				     strcmp(name, rname) == 0) &&
				    (value == NULL ||
				     strcmp(value, rvalue) == 0))
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_HDRINSERT:
	  {
#ifdef SMFIR_INSHEADER
		int idx = -1;
		char *name = NULL;
		char *value = NULL;

		if (lua_gettop(l) >= 3)
		{
			if (!lua_isstring(l, 3))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			name = (char *) lua_tostring(l, 3);
		}

		if (lua_gettop(l) >= 4)
		{
			if (!lua_isstring(l, 4))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			value = (char *) lua_tostring(l, 4);
		}

		if (lua_gettop(l) == 5)
		{
			if (!lua_isnumber(l, 5))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			idx = lua_tonumber(l, 5);
		}

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_INSHEADER)
			{
				int ridx;
				char *rname;
				char *rvalue;

				memcpy(&ridx, r->eom_rdata, MILTER_LEN_BYTES);
				ridx = ntohl(ridx);
				rname = r->eom_rdata + MILTER_LEN_BYTES;
				rvalue = r->eom_rdata + MILTER_LEN_BYTES +
				         strlen(rname) + 1;

				if ((name == NULL ||
				     strcmp(name, rname) == 0) &&
				    (value == NULL ||
				     strcmp(value, rvalue) == 0) &&
				    (idx == -1 || ridx == idx))
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}
#endif /* SMFIR_INSHEADER */

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_HDRCHANGE:
	  {
		int idx = -1;
		char *name = NULL;
		char *value = NULL;

		if (lua_gettop(l) >= 3)
		{
			if (!lua_isstring(l, 3))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			name = (char *) lua_tostring(l, 3);
		}

		if (lua_gettop(l) >= 4)
		{
			if (!lua_isstring(l, 4))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			value = (char *) lua_tostring(l, 4);
		}

		if (lua_gettop(l) == 5)
		{
			if (!lua_isnumber(l, 5))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			idx = lua_tonumber(l, 4);
		}

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_CHGHEADER)
			{
				int ridx;
				char *rname;
				char *rvalue;

				memcpy(&ridx, r->eom_rdata, MILTER_LEN_BYTES);
				ridx = ntohl(ridx);
				rname = r->eom_rdata + MILTER_LEN_BYTES;
				rvalue = r->eom_rdata + MILTER_LEN_BYTES +
				         strlen(rname) + 1;

				if ((name == NULL ||
				     strcmp(name, rname) == 0) &&
				    (value == NULL ||
				     strcmp(value, rvalue) == 0) &&
				    (idx == -1 || ridx == idx))
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_HDRDELETE:
	  {
		int idx = -1;
		char *name = NULL;

		if (lua_gettop(l) >= 3)
		{
			if (!lua_isstring(l, 3))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			name = (char *) lua_tostring(l, 3);
		}

		if (lua_gettop(l) == 4)
		{
			if (!lua_isnumber(l, 4))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			idx = lua_tonumber(l, 4);
		}

		if (lua_gettop(l) == 5)
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_CHGHEADER)
			{
				int ridx;
				char *rname;
				char *rvalue;

				memcpy(&ridx, r->eom_rdata, MILTER_LEN_BYTES);
				ridx = ntohl(ridx);
				rname = r->eom_rdata + MILTER_LEN_BYTES;
				rvalue = r->eom_rdata + MILTER_LEN_BYTES +
				         strlen(rname) + 1;

				if ((name == NULL ||
				     strcmp(name, rname) == 0) &&
				    rvalue[0] == '\0' &&
				    (idx == -1 || ridx == idx))
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_RCPTADD:
	  {
		char *rcpt;

		if (lua_gettop(l) != 3 ||
		    !lua_isstring(l, 3))
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		rcpt = (char *) lua_tostring(l, 3);

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_ADDRCPT)
			{
				char *rname;

				rname = r->eom_rdata;

				if (strcmp(rcpt, rname) == 0)
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_RCPTDELETE:
	  {
		char *rcpt;

		if (lua_gettop(l) != 3 ||
		    !lua_isstring(l, 3))
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		rcpt = (char *) lua_tostring(l, 3);

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_DELRCPT)
			{
				char *rname;

				rname = r->eom_rdata;

				if (strcmp(rcpt, rname) == 0)
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  case MT_BODYCHANGE:
	  {
		char *newbody = NULL;

		if (lua_gettop(l) < 2 || lua_gettop(l) > 3 ||
		    (lua_gettop(l) == 3 && !lua_isstring(l, 3)))
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		if (lua_gettop(l) == 3)
			newbody = (char *) lua_tostring(l, 3);

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_REPLBODY)
			{
				char *rbody;

				rbody = r->eom_rdata;

				if (newbody == NULL ||
				    (strlen(newbody) == r->eom_rlen &&
				     memcmp(rbody, newbody, r->eom_rlen) == 0))
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

#ifdef SMFIR_QUARANTINE
	  case MT_QUARANTINE:
	  {
		char *reason = NULL;

		if (lua_gettop(l) < 2 || lua_gettop(l) > 3 ||
		    (lua_gettop(l) == 3 && !lua_isstring(l, 3)))
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		if (lua_gettop(l) == 3)
			reason = (char *) lua_tostring(l, 3);

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_QUARANTINE)
			{
				char *rreason;

				rreason = r->eom_rdata;

				if (reason == NULL ||
				    strcmp(reason, rreason) == 0)
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }
#endif /* SMFIR_QUARANTINE */

	  case MT_SMTPREPLY:
	  {
		char *smtp = NULL;
		char *esc = NULL;
		char *text = NULL;

		if (lua_gettop(l) < 3 || !lua_isstring(l, 3))
		{
			lua_pushstring(l, "mt.eom_check(): Invalid argument");
			lua_error(l);
		}

		smtp = (char *) lua_tostring(l, 3);

		if (lua_gettop(l) >= 4)
		{
			if (!lua_isstring(l, 4))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			esc = (char *) lua_tostring(l, 4);
		}

		if (lua_gettop(l) == 5)
		{
			if (!lua_isstring(l, 5))
			{
				lua_pushstring(l,
				               "mt.eom_check(): Invalid argument");
				lua_error(l);
			}

			text = (char *) lua_tostring(l, 5);
		}

		lua_pop(l, lua_gettop(l));

		for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
		{
			if (r->eom_request == SMFIR_REPLYCODE)
			{
				char rbuf[BUFRSZ];

				snprintf(rbuf, sizeof rbuf, "%s%s%s%s%s",
				         smtp,
				         esc == NULL ? "" : " ", esc,
				         text == NULL ? "" : " ", text);

				if (strcmp(rbuf, (char *) r->eom_rdata) == 0)
				{
					lua_pushboolean(l, 1);
					return 1;
				}
			}
		}

		lua_pushboolean(l, 0);
		return 1;
	  }

	  default:
		lua_pushstring(l, "mt.eom_check(): Invalid argument");
		lua_error(l);
	}

	return 1;
}

/*
**  MT_ABORT -- send transaction abort notice
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	nil (on the Lua stack)
*/

int
mt_abort(lua_State *l)
{
	struct mt_context *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.abort(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	if (!mt_milter_write(ctx->ctx_fd, SMFIC_ABORT, NULL, 0))
	{
		lua_pushstring(l, "mt.milter_write() failed");
		return 1;
	}

	ctx->ctx_state = STATE_HELO;

	if (verbose > 0)
	{
		fprintf(stdout, "%s: ABORT sent on fd %d\n",
		        progname, ctx->ctx_fd);
	}

	lua_pushnil(l);

	return 1;
}

/*
**  MT_GETREPLY -- get last reply
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	Last reply received, as an integer (on the Lua stack).
*/

int
mt_getreply(lua_State *l)
{
	struct mt_context *ctx;

	assert(l != NULL);

	if (lua_gettop(l) != 1 ||
	    !lua_islightuserdata(l, 1))
	{
		lua_pushstring(l, "mt.getreply(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	lua_pop(l, 1);

	lua_pushnumber(l, ctx->ctx_response);

	return 1;
}

/*
**  MT_GETHEADER -- retrieve a header field added during EOM
**
**  Parameters:
**  	l -- Lua state
**
**  Return value:
**   	Last reply received, as a string (on the Lua stack).
*/

int
mt_getheader(lua_State *l)
{
	int idx;
	char *name;
	struct mt_context *ctx;
	struct mt_eom_request *r;

	assert(l != NULL);

	if (lua_gettop(l) != 3 ||
	    !lua_islightuserdata(l, 1) ||
	    !lua_isstring(l, 2) ||
	    !lua_isnumber(l, 3))
	{
		lua_pushstring(l, "mt.getheader(): Invalid argument");
		lua_error(l);
	}

	ctx = (struct mt_context *) lua_touserdata(l, 1);
	name = (char *) lua_tostring(l, 2);
	idx = lua_tonumber(l, 3);
	lua_pop(l, 3);

	for (r = ctx->ctx_eomreqs; r != NULL; r = r->eom_next)
	{
#ifdef SMFIR_INSHEADER
		if (r->eom_request == SMFIR_ADDHEADER ||
		    r->eom_request == SMFIR_INSHEADER)
#else /* SMFIR_INSHEADER */
		if (r->eom_request == SMFIR_ADDHEADER)
#endif /* SMFIR_INSHEADER */
		{
			char *rname;
			char *rvalue;

#ifdef SMFIR_INSHEADER
			if (r->eom_request == SMFIR_INSHEADER)
			{
				rname = r->eom_rdata + MILTER_LEN_BYTES;
				rvalue = r->eom_rdata + MILTER_LEN_BYTES +
				         strlen(rname) + 1;
			}
			else
#endif /* SMFIR_INSHEADER */
			{
				rname = r->eom_rdata;
				rvalue = r->eom_rdata + strlen(rname) + 1;
			}

			if (strcmp(name, rname) == 0 && rvalue != NULL)
			{
				if (idx == 0)
				{
					lua_pushstring(l, rvalue);
					return 1;
				}
				else
				{
					idx--;
				}
			}
		}
	}

	lua_pushnil(l);

	return 1;
}

/*
**  USAGE -- print usage message
** 
**  Parameters:
**  	Not now.  Maybe later.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [options]\n"
	                "\t-D name[=value]\tdefine global variable\n"
	                "\t-s script      \tscript to run (default = stdin)\n"
	                "\t-u             \treport usage statistics\n"
	                "\t-v             \tverbose mode\n"
	                "\t-V             \tprint version number and exit\n"
	                "\t-w             \tdon't wait for child at shutdown\n",
	                progname, progname);

	return EX_USAGE;
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	int c;
	int status;
	int fd;
	int retval = 0;
	ssize_t rlen;
	char *p;
	char *script = NULL;
	lua_State *l;
	struct mt_lua_io io;
	struct stat s;

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	verbose = 0;
	filterpid = 0;
	tmo = DEFTIMEOUT;
	rusage = FALSE;
	nowait = FALSE;

	l = lua_newstate(mt_lua_alloc, NULL);
	if (l == NULL)
	{
		fprintf(stderr, "%s: unable to allocate new Lua state\n",
		        progname);
		return 1;
	}

	luaL_openlibs(l);

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'D':
			p = strchr(optarg, '=');
			if (p != NULL)
			{
				*p = '\0';
				lua_pushstring(l, p + 1);
			}
			else
			{
				lua_pushnumber(l, 1);
			}

			lua_setglobal(l, optarg);

			break;

		  case 's':
			if (script != NULL)
			{
				fprintf(stderr,
				        "%s: multiple use of '-%c' not permitted\n",
				        progname, c);
				lua_close(l);
				return EX_USAGE;
			}

			script = optarg;
			break;

		  case 'u':
			rusage = TRUE;
			break;

		  case 'v':
			verbose++;
			break;

		  case 'V':
			fprintf(stdout, "%s: %s v%s\n", progname, MT_PRODUCT,
			        MT_VERSION);
			return 0;

		  case 'w':
			nowait = TRUE;
			break;

		  default:
			lua_close(l);
			return usage();
		}
	}

	if (optind != argc)
	{
		lua_close(l);
		return usage();
	}

	io.lua_io_done = FALSE;

	if (script != NULL)
	{
		fd = open(script, O_RDONLY);
		if (fd < 0)
		{
			fprintf(stderr, "%s: %s: open(): %s\n", progname,
			        script, strerror(errno));
			lua_close(l);
			return 1;
		}

		if (fstat(fd, &s) != 0)
		{
			fprintf(stderr, "%s: %s: fstat(): %s\n", progname,
			        script, strerror(errno));
			close(fd);
			lua_close(l);
			return 1;
		}

		io.lua_io_script = (const char *) malloc(s.st_size);
		if (io.lua_io_script == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n", progname,
			        strerror(errno));
			close(fd);
			lua_close(l);
			return 1;
		}

		rlen = read(fd, (void *) io.lua_io_script, s.st_size);
		if (rlen != s.st_size)
		{
			fprintf(stderr,
			        "%s: %s: read() returned %zu (expecting %ld)\n",
			        progname, script, rlen, (long) s.st_size);
			free((void *) io.lua_io_script);
			close(fd);
			lua_close(l);
			return 1;
		}

		io.lua_io_scriptlen = (size_t) s.st_size;

		close(fd);
	}
	else
	{
		io.lua_io_script = NULL;
	}

	/* register functions */
#if LUA_VERSION_NUM == 502
        luaL_newlib(l, mt_library);
	lua_setglobal(l, "mt");
#else /* LUA_VERSION_NUM == 502 */
	luaL_register(l, "mt", mt_library);
#endif /* LUA_VERSION_NUM == 502 */
	lua_pop(l, 1);

	/* register constants */
	lua_pushnumber(l, MT_HDRINSERT);
	lua_setglobal(l, "MT_HDRINSERT");
	lua_pushnumber(l, MT_HDRADD);
	lua_setglobal(l, "MT_HDRADD");
	lua_pushnumber(l, MT_HDRCHANGE);
	lua_setglobal(l, "MT_HDRCHANGE");
	lua_pushnumber(l, MT_HDRDELETE);
	lua_setglobal(l, "MT_HDRDELETE");
	lua_pushnumber(l, MT_RCPTADD);
	lua_setglobal(l, "MT_RCPTADD");
	lua_pushnumber(l, MT_RCPTDELETE);
	lua_setglobal(l, "MT_RCPTDELETE");
	lua_pushnumber(l, MT_BODYCHANGE);
	lua_setglobal(l, "MT_BODYCHANGE");
	lua_pushnumber(l, MT_QUARANTINE);
	lua_setglobal(l, "MT_QUARANTINE");
	lua_pushnumber(l, MT_SMTPREPLY);
	lua_setglobal(l, "MT_SMTPREPLY");

	lua_pushnumber(l, SMFIR_CONTINUE);
	lua_setglobal(l, "SMFIR_CONTINUE");
	lua_pushnumber(l, SMFIR_ACCEPT);
	lua_setglobal(l, "SMFIR_ACCEPT");
	lua_pushnumber(l, SMFIR_REJECT);
	lua_setglobal(l, "SMFIR_REJECT");
	lua_pushnumber(l, SMFIR_TEMPFAIL);
	lua_setglobal(l, "SMFIR_TEMPFAIL");
	lua_pushnumber(l, SMFIR_DISCARD);
	lua_setglobal(l, "SMFIR_DISCARD");
	lua_pushnumber(l, SMFIR_REPLYCODE);
	lua_setglobal(l, "SMFIR_REPLYCODE");
#ifdef SMFIR_SKIP
	lua_pushnumber(l, SMFIR_SKIP);
	lua_setglobal(l, "SMFIR_SKIP");
#endif /* SMFIR_SKIP */

	lua_pushnumber(l, SMFIC_CONNECT);
	lua_setglobal(l, "SMFIC_CONNECT");
	lua_pushnumber(l, SMFIC_HELO);
	lua_setglobal(l, "SMFIC_HELO");
	lua_pushnumber(l, SMFIC_MAIL);
	lua_setglobal(l, "SMFIC_MAIL");
	lua_pushnumber(l, SMFIC_RCPT);
	lua_setglobal(l, "SMFIC_RCPT");

	lua_pushnumber(l, SMFIP_NOCONNECT);
	lua_setglobal(l, "SMFIP_NOCONNECT");
	lua_pushnumber(l, SMFIP_NOHELO);
	lua_setglobal(l, "SMFIP_NOHELO");
	lua_pushnumber(l, SMFIP_NOMAIL);
	lua_setglobal(l, "SMFIP_NOMAIL");
	lua_pushnumber(l, SMFIP_NORCPT);
	lua_setglobal(l, "SMFIP_NORCPT");
	lua_pushnumber(l, SMFIP_NOBODY);
	lua_setglobal(l, "SMFIP_NOBODY");
	lua_pushnumber(l, SMFIP_NOHDRS);
	lua_setglobal(l, "SMFIP_NOHDRS");
	lua_pushnumber(l, SMFIP_NOEOH);
	lua_setglobal(l, "SMFIP_NOEOH");
#ifdef SMFIP_NR_HDR
	lua_pushnumber(l, SMFIP_NR_HDR);
	lua_setglobal(l, "SMFIP_NR_HDR");
#endif /* SMFIP_NR_HDR */
#ifdef SMFIP_NOHREPL
	lua_pushnumber(l, SMFIP_NOHREPL);
	lua_setglobal(l, "SMFIP_NOHREPL");
#endif /* SMFIP_NOHREPL */
#ifdef SMFIP_NOUNKNOWN
	lua_pushnumber(l, SMFIP_NOUNKNOWN);
	lua_setglobal(l, "SMFIP_NOUNKNOWN");
#endif /* SMFIP_NOUNKNOWN */
#ifdef SMFIP_NODATA
	lua_pushnumber(l, SMFIP_NODATA);
	lua_setglobal(l, "SMFIP_NODATA");
#endif /* SMFIP_NODATA */
#ifdef SMFIP_SKIP
	lua_pushnumber(l, SMFIP_SKIP);
	lua_setglobal(l, "SMFIP_SKIP");
#endif /* SMFIP_SKIP */
#ifdef SMFIP_RCPT_REJ
	lua_pushnumber(l, SMFIP_RCPT_REJ);
	lua_setglobal(l, "SMFIP_RCPT_REJ");
#endif /* SMFIP_RCPT_REJ */
	lua_pushnumber(l, SMFIP_NR_CONN);
	lua_setglobal(l, "SMFIP_NR_CONN");
	lua_pushnumber(l, SMFIP_NR_HELO);
	lua_setglobal(l, "SMFIP_NR_HELO");
	lua_pushnumber(l, SMFIP_NR_MAIL);
	lua_setglobal(l, "SMFIP_NR_MAIL");
	lua_pushnumber(l, SMFIP_NR_RCPT);
	lua_setglobal(l, "SMFIP_NR_RCPT");
	lua_pushnumber(l, SMFIP_NR_DATA);
	lua_setglobal(l, "SMFIP_NR_DATA");
	lua_pushnumber(l, SMFIP_NR_UNKN);
	lua_setglobal(l, "SMFIP_NR_UNKN");
	lua_pushnumber(l, SMFIP_NR_EOH);
	lua_setglobal(l, "SMFIP_NR_EOH");
	lua_pushnumber(l, SMFIP_NR_BODY);
	lua_setglobal(l, "SMFIP_NR_BODY");
#ifdef SMFIP_HDR_LEADSPC
	lua_pushnumber(l, SMFIP_HDR_LEADSPC);
	lua_setglobal(l, "SMFIP_HDR_LEADSPC");
#endif /* SMFIP_HDR_LEADSPC */
#ifdef SMFIP_MDS_256K
	lua_pushnumber(l, SMFIP_MDS_256K);
	lua_setglobal(l, "SMFIP_MDS_256K");
#endif /* SMFIP_MDS_256K */
#ifdef SMFIP_MDS_1M
	lua_pushnumber(l, SMFIP_MDS_1M);
	lua_setglobal(l, "SMFIP_MDS_1M");
#endif /* SMFIP_MDS_1M */
#ifdef SMFIP_TEST
	lua_pushnumber(l, SMFIP_TEST);
	lua_setglobal(l, "SMFIP_TEST");
#endif /* SMFIP_TEST */

	lua_pushnumber(l, SMFIF_ADDHDRS);
	lua_setglobal(l, "SMFIF_ADDHDRS");
	lua_pushnumber(l, SMFIF_CHGBODY);
	lua_setglobal(l, "SMFIF_CHGBODY");
	lua_pushnumber(l, SMFIF_MODBODY);
	lua_setglobal(l, "SMFIF_MODBODY");
	lua_pushnumber(l, SMFIF_ADDRCPT);
	lua_setglobal(l, "SMFIF_ADDRCPT");
	lua_pushnumber(l, SMFIF_DELRCPT);
	lua_setglobal(l, "SMFIF_DELRCPT");
	lua_pushnumber(l, SMFIF_CHGHDRS);
	lua_setglobal(l, "SMFIF_CHGHDRS");
#ifdef SMFIF_QUARANTINE
	lua_pushnumber(l, SMFIF_QUARANTINE);
	lua_setglobal(l, "SMFIF_QUARANTINE");
#endif /* SMFIF_QUARANTINE */
#ifdef SMFIF_CHGFROM
	lua_pushnumber(l, SMFIF_CHGFROM);
	lua_setglobal(l, "SMFIF_CHGFROM");
#endif /* SMFIF_CHGFROM */
#ifdef SMFIF_ADDRCPT_PAR
	lua_pushnumber(l, SMFIF_ADDRCPT_PAR);
	lua_setglobal(l, "SMFIF_ADDRCPT_PAR");
#endif /* SMFIF_ADDRCPT_PAR */
#ifdef SMFIF_SETSYMLIST
	lua_pushnumber(l, SMFIF_SETSYMLIST);
	lua_setglobal(l, "SMFIF_SETSYMLIST");
#endif /* SMFIF_SETSYMLIST */

#if LUA_VERSION_NUM == 502
	switch (lua_load(l, mt_lua_reader, (void *) &io,
	                 script == NULL ? "(stdin)" : script, NULL))
#else /* LUA_VERSION_NUM == 502 */
	switch (lua_load(l, mt_lua_reader, (void *) &io,
	                 script == NULL ? "(stdin)" : script))
#endif /* LUA_VERSION_NUM == 502 */
	{
	  case 0:
		break;

	  case LUA_ERRSYNTAX:
	  case LUA_ERRMEM:
		if (lua_isstring(l, 1))
		{
			fprintf(stderr, "%s: %s: %s\n", progname,
			        script == NULL ? "(stdin)" : script,
			        lua_tostring(l, 1));
		}
		lua_close(l);
		if (io.lua_io_script != NULL)
			free((void *) io.lua_io_script);
		return 1;

	  default:
		assert(0);
	}

	(void) srandom(time(NULL));

	status = lua_pcall(l, 0, LUA_MULTRET, 0);
	if (lua_gettop(l) == 1 && lua_isstring(l, 1))
	{
		fprintf(stderr, "%s: %s: %s\n", progname,
		        script == NULL ? "(stdin)" : script,
		        lua_tostring(l, 1));
	}

	if (rusage)
	{
		struct rusage u;

		if (getrusage(RUSAGE_SELF, &u) != 0)
		{
			fprintf(stderr,
			        "%s: getrusage(RUSAGE_SELF): %s\n",
			        progname, strerror(errno));

			retval = 2;
		}

		fprintf(stdout, "%s: self:  user %u.%06u, system %u.%06u\n",
		        progname,
		        (unsigned) u.ru_utime.tv_sec,
		        (unsigned) u.ru_utime.tv_usec,
		        (unsigned) u.ru_stime.tv_sec,
		        (unsigned) u.ru_stime.tv_usec);
	}

	if (status != 0)
		retval = 1;

	lua_close(l);
	if (io.lua_io_script != NULL)
		free((void *) io.lua_io_script);

	if (filterpid != 0)
	{
		if (kill(filterpid, SIGTERM) != 0)
		{
			fprintf(stderr, "%s: %d: kill() %s\n", progname,
			        filterpid, strerror(errno));
		}
		else if (!nowait)
		{
			if (verbose > 1)
			{
				fprintf(stdout,
				        "%s: waiting for process %d\n",
				        progname, filterpid);
			}

			(void) wait(&status);

			if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			{
				fprintf(stderr,
				        "%s: filter process exited with status %d\n",
				        progname, WEXITSTATUS(status));

				retval = 1;
			}
			else if (WIFSIGNALED(status) &&
			         WTERMSIG(status) != SIGTERM)
			{
				fprintf(stderr,
				        "%s: filter process died with signal %d\n",
				        progname, WTERMSIG(status));

				retval = 1;
			}
		}
	}

	if (rusage && !nowait)
	{
		struct rusage u;

		if (getrusage(RUSAGE_CHILDREN, &u) != 0)
		{
			fprintf(stderr,
			        "%s: getrusage(RUSAGE_CHILDREN): %s\n",
			        progname, strerror(errno));

			retval = 2;
		}

		fprintf(stdout, "%s: child: user %u.%06u, system %u.%06u\n",
		        progname,
		        (unsigned) u.ru_utime.tv_sec,
		        (unsigned) u.ru_utime.tv_usec,
		        (unsigned) u.ru_stime.tv_sec,
		        (unsigned) u.ru_stime.tv_usec);
	}

	return retval;
}
