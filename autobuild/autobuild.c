/*
**  Copyright (c) 2012, 2013, The Trusted Domain Project.
**  	All rights reserved.
*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sysexits.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>

#include <jansson.h>

#define	JSON_ALWAYS	"always"
#define	JSON_COMBINE	"combine"
#define	JSON_EACH	"each"

#define	AUTORECONF	"autoreconf"
#define	CONFIGURE	"./configure"
#define	MAKE		"make"
#define	DISTCHECK	"distcheck"
#define	CLEAN		"clean"

#define	BUFRSZ		2048
#define	TEMPLATE	"/tmp/abXXXXXX"

#ifndef MIN
# define MIN(a,b)	((a) < (b) ? (a) : (b))
#endif /* ! MIN */
#ifndef MAX
# define MAX(a,b)	((a) > (b) ? (a) : (b))
#endif /* ! MAX */

char *progname;

/*
**  DUMPARGS -- dump argument vector
**
**  Parameters:
**  	where -- output stream
**  	args -- argument vector
**
**  Return value:
**  	None.
*/

void
dumpargs(FILE *where, const char **args)
{
	int n;

	for (n = 0; args[n] != NULL; n++)
		fprintf(where, "%s%s\n", n == 0 ? "" : "\t", args[n]);
}

/*
**  USAGE -- print usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_USAGE
*/

int
usage(void)
{
	fprintf(stderr, "%s: usage: %s [options] descr-file\n"
	                "\t-c\tshow combinations and exit\n"
	                "\t-n\tparse descr-file and exit\n"
	                "\t-t\tshow timestamps\n"
	                "\t-v\tverbose mode\n", progname, progname);

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
	int status;
	int m;
	int n;
	int fd;
	int showcombos = 0;
	int verbose = 0;
	int timestamps = 0;
	int confonly = 0;
	pid_t child;
	size_t combos;
	size_t asz;
	size_t c;
	size_t d;
	size_t bits;
	size_t nopts;
	size_t neach = 1;
	size_t nargs;
	size_t maxopts;
	size_t meach = 0;
	size_t xeach;
	json_t *j;
	json_t *node;
	json_t *always = NULL;
	json_t *combine = NULL;
	json_t *each = NULL;
	json_error_t err;
	void *iter;
	char *p;
	char *key;
	char *descr;
	const char **args;
	char buf[BUFRSZ];
	char fn[MAXPATHLEN + 1];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, "cntv")) != -1)
	{
		switch (c)
		{
		  case 'c':
			showcombos++;
			break;

		  case 'n':
			confonly++;
			break;

		  case 't':
			timestamps++;
			break;

		  case 'v':
			verbose++;
			break;

		  default:
			return usage();
		}
	}

	if (optind >= argc)
		return usage();

	descr = argv[optind];
	j = json_load_file(descr, 0, &err);
	if (j == NULL)
	{
		fprintf(stderr, "%s: JSON input error from %s:\n"
		                "\ttext = \"%s\"\n"
		                "\tsource = \"%s\"\n"
		                "\tline = %d\n"
		                "\tcolumn = %d\n"
		                "\toffset = %ld\n",
		        progname, descr, err.text, err.source, err.line,
		        err.column, err.position);
		return EX_DATAERR;
	}

	/* the top has to be an object */
	if (!json_is_object(j))
	{
		fprintf(stderr, "%s: %s: root object is not an object\n",
		        progname, descr);
		json_decref(j);
		return EX_DATAERR;
	}

	/* ensure there are no top-level objects we don't expect */
	for (iter = json_object_iter(j);
	     iter != NULL;
	     iter = json_object_iter_next(j, iter))
	{
		key = (char *) json_object_iter_key(iter);
		node = json_object_iter_value(iter);

		if (strcasecmp(key, JSON_ALWAYS) != 0 &&
		    strcasecmp(key, JSON_EACH) != 0 &&
		    strcasecmp(key, JSON_COMBINE) != 0)
		{
			fprintf(stderr,
			        "%s: %s: unexpected root object \"%s\"\n",
			        progname, descr, key);
			json_decref(j);
			return EX_DATAERR;
		}
		else if (!json_is_array(node))
		{
			fprintf(stderr,
			        "%s: %s: root object \"%s\" is not an array\n",
			        progname, descr, key);
			json_decref(j);
			return EX_DATAERR;
		}
		else if (strcasecmp(key, JSON_ALWAYS) == 0)
		{
			always = node;
		}
		else if (strcasecmp(key, JSON_EACH) == 0)
		{
			each = node;
		}
		else
		{
			combine = node;
		}
	}

	if (confonly > 0)
	{
		json_decref(j);
		return EX_OK;
	}

	nargs = 2;
	if (always != NULL)
		nargs += json_array_size(always);
	if (combine == NULL)
		nopts = 0;
	else
		nopts = json_array_size(combine);
	if (each == NULL)
	{
		neach = 1;
	}
	else
	{
		neach = json_array_size(each);
		for (n = 0; n < neach; n++)
		{
			node = json_array_get(each, n);
			if (json_is_array(node))
				meach = MAX(json_array_size(node), meach);
		}
	}

	for (n = 0; n < nopts; n++)
	{
		node = json_array_get(combine, n);

		switch (json_typeof(node))
		{
		  case JSON_ARRAY:
			for (m = 0; m < json_array_size(node); m++)
			{
				if (!json_is_string(json_array_get(node, m)))
				{
					fprintf(stderr,
					        "%s: %s: combine object at index %d is an array containing non-strings\n",
					        progname, descr, n);
					return EX_DATAERR;
				}

				nargs++;
			}

			break;

		  case JSON_STRING:
			nargs++;
			break;

		  default:
			fprintf(stderr,
			        "%s: %s: combine object at index %d is not a string or array\n",
			        progname, descr, n);
			return EX_DATAERR;
		}
	}

	asz = sizeof(char *) * (nargs + nopts + meach + 2);
	args = (const char **) malloc(asz);
	if (args == NULL)
	{
		fprintf(stderr, "%s: malloc(): %s\n", progname,
		        strerror(errno));
		return EX_OSERR;
	}

	combos = (size_t) pow(2, nopts) * neach;

	if (verbose > 1)
	{
		fprintf(stdout, "%s: max %d arguments, %d combinations\n",
		        progname, nargs + nopts, combos);
	}

	/* autoreconf */
	args[0] = AUTORECONF;
	args[1] = "-v";
	args[2] = "-i";
	args[3] = NULL;

	if (!showcombos)
	{
		strncpy(fn, TEMPLATE, sizeof fn);
		fd = mkstemp(fn);
		if (fd < 0)
		{
			fprintf(stderr, "%s: mkstemp(): %s\n", progname,
		        	strerror(errno));
			return EX_OSERR;
		}
		(void) unlink(fn);

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  case 0:
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) execvp(args[0], (char * const *) args);
			fprintf(stderr, "%s: execvp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  default:
			n = wait(&status);
			if (n == -1)
			{
				fprintf(stderr, "%s: wait(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}
			else if (WIFSIGNALED(status) ||
			         WEXITSTATUS(status) != 0)
			{
				if (WIFSIGNALED(status))
				{
					fprintf(stderr,
					        "%s: clean died with signal %d\n",
					        progname, WTERMSIG(status));
				}
				else
				{
					fprintf(stderr,
					        "%s: clean exited with status %d\n",
					        progname, WEXITSTATUS(status));
				}

				(void) lseek(fd, 0, SEEK_SET);

				dumpargs(stdout, args);

				for (;;)
				{
					n = read(fd, buf, sizeof buf);
					(void) fwrite(buf, 1, n, stdout);
					if (n < sizeof buf)
						break;
				}

				close(fd);
				free(args);
				json_decref(j);
				return 1;
			}

			break;
		}

		/* clean up */
		close(fd);
	}

	for (c = 0; c < combos; c++)
	{
		xeach = c % neach;

		memset(args, '\0', asz);
		bits = c;

		args[0] = CONFIGURE;
		n = 1;

		/* add the "always" arguments */
		for (d = 0; d < json_array_size(always); d++)
		{
			node = json_array_get(always, d);
			args[n++] = json_string_value(node);
		}

		/* select the "each" argument */
		if (each != NULL)
		{
			node = json_array_get(each, xeach);
			if (json_is_string(node))
			{
				args[n++] = json_string_value(node);
			}
			else
			{
				json_t *sub;

				for (m = 0;
				     m < json_array_size(node);
				     m++)
				{
					sub = json_array_get(node, m);
					args[n++] = json_string_value(sub);
				}
			}
		}

		/* add the new combination of options */
		for (d = 0; d < nopts; d++)
		{
			if ((c / neach) & (1 << d))
			{
				node = json_array_get(combine, d);

				if (json_is_string(node))
				{
					args[n++] = json_string_value(node);
				}
				else
				{
					json_t *sub;

					for (m = 0;
					     m < json_array_size(node);
					     m++)
					{
						sub = json_array_get(node, m);
						args[n++] = json_string_value(sub);
					}
				}
			}
		}

		if (showcombos)
		{
			dumpargs(stdout, args);
			continue;
		}

		if (verbose)
		{
			if (timestamps)
			{
				time_t now;

				(void) time(&now);
				fprintf(stdout, "%s: %s", progname,
				        ctime(&now));
			}
			
			fprintf(stdout, "%s: ", progname);
			dumpargs(stdout, args);
		}

		/* ./configure */
		strncpy(fn, TEMPLATE, sizeof fn);
		fd = mkstemp(fn);
		if (fd < 0)
		{
			fprintf(stderr, "%s: mkstemp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}
		(void) unlink(fn);

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  case 0:
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) execvp(args[0], (char * const *) args);
			fprintf(stderr, "%s: execvp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  default:
			n = wait(&status);
			if (n == -1)
			{
				fprintf(stderr, "%s: wait(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}
			else if (WIFSIGNALED(status) ||
			         WEXITSTATUS(status) != 0)
			{
				if (WIFSIGNALED(status))
				{
					fprintf(stderr,
					        "%s: configure died with signal %d\n",
					        progname, WTERMSIG(status));
				}
				else
				{
					fprintf(stderr,
					        "%s: configure exited with status %d\n",
					        progname, WEXITSTATUS(status));
				}

				(void) lseek(fd, 0, SEEK_SET);

				dumpargs(stdout, args);

				for (;;)
				{
					n = read(fd, buf, sizeof buf);
					(void) fwrite(buf, 1, n, stdout);
					if (n < sizeof buf)
						break;
				}

				close(fd);
				free(args);
				json_decref(j);
				return 1;
			}

			break;
		}

		close(fd);

		/* make */
		args[0] = MAKE;
		args[1] = NULL;

		strncpy(fn, TEMPLATE, sizeof fn);
		fd = mkstemp(fn);
		if (fd < 0)
		{
			fprintf(stderr, "%s: mkstemp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}
		(void) unlink(fn);

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  case 0:
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) execvp(args[0], (char * const *) args);
			fprintf(stderr, "%s: execvp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  default:
			n = wait(&status);
			if (n == -1)
			{
				fprintf(stderr, "%s: wait(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}
			else if (WIFSIGNALED(status) ||
			         WEXITSTATUS(status) != 0)
			{
				if (WIFSIGNALED(status))
				{
					fprintf(stderr,
					        "%s: make died with signal %d\n",
					        progname, WTERMSIG(status));
				}
				else
				{
					fprintf(stderr,
					        "%s: make exited with status %d\n",
					        progname, WEXITSTATUS(status));
				}

				(void) lseek(fd, 0, SEEK_SET);

				dumpargs(stdout, args);

				for (;;)
				{
					n = read(fd, buf, sizeof buf);
					(void) fwrite(buf, 1, n, stdout);
					if (n < sizeof buf)
						break;
				}

				close(fd);
				free(args);
				json_decref(j);
				return 1;
			}

			break;
		}

		close(fd);

		/* make distcheck */
		args[0] = MAKE;
		args[1] = DISTCHECK;
		args[2] = NULL;

		strncpy(fn, TEMPLATE, sizeof fn);
		fd = mkstemp(fn);
		if (fd < 0)
		{
			fprintf(stderr, "%s: mkstemp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}
		(void) unlink(fn);

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  case 0:
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) execvp(args[0], (char * const *) args);
			fprintf(stderr, "%s: execvp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  default:
			n = wait(&status);
			if (n == -1)
			{
				fprintf(stderr, "%s: wait(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}
			else if (WIFSIGNALED(status) ||
			         WEXITSTATUS(status) != 0)
			{
				if (WIFSIGNALED(status))
				{
					fprintf(stderr,
					        "%s: distcheck died with signal %d\n",
					        progname, WTERMSIG(status));
				}
				else
				{
					fprintf(stderr,
					        "%s: distcheck exited with status %d\n",
					        progname, WEXITSTATUS(status));
				}

				(void) lseek(fd, 0, SEEK_SET);

				dumpargs(stdout, args);

				for (;;)
				{
					n = read(fd, buf, sizeof buf);
					(void) fwrite(buf, 1, n, stdout);
					if (n < sizeof buf)
						break;
				}

				close(fd);
				free(args);
				json_decref(j);
				return 1;
			}

			break;
		}

		/* clean up */
		close(fd);

		/* make clean */
		args[0] = MAKE;
		args[1] = CLEAN;
		args[2] = NULL;

		strncpy(fn, TEMPLATE, sizeof fn);
		fd = mkstemp(fn);
		if (fd < 0)
		{
			fprintf(stderr, "%s: mkstemp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;
		}
		(void) unlink(fn);

		child = fork();
		switch (child)
		{
		  case -1:
			fprintf(stderr, "%s: fork(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  case 0:
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) execvp(args[0], (char * const *) args);
			fprintf(stderr, "%s: execvp(): %s\n", progname,
			        strerror(errno));
			return EX_OSERR;

		  default:
			n = wait(&status);
			if (n == -1)
			{
				fprintf(stderr, "%s: wait(): %s\n", progname,
				        strerror(errno));
				return EX_OSERR;
			}
			else if (WIFSIGNALED(status) ||
			         WEXITSTATUS(status) != 0)
			{
				if (WIFSIGNALED(status))
				{
					fprintf(stderr,
					        "%s: clean died with signal %d\n",
					        progname, WTERMSIG(status));
				}
				else
				{
					fprintf(stderr,
					        "%s: clean exited with status %d\n",
					        progname, WEXITSTATUS(status));
				}

				(void) lseek(fd, 0, SEEK_SET);

				dumpargs(stdout, args);

				for (;;)
				{
					n = read(fd, buf, sizeof buf);
					(void) fwrite(buf, 1, n, stdout);
					if (n < sizeof buf)
						break;
				}

				close(fd);
				free(args);
				json_decref(j);
				return 1;
			}

			break;
		}

		/* clean up */
		close(fd);
	}

	return 0;
}
