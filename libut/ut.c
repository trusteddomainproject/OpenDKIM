/*
**  Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
*/

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

/* libut includes */
#include "ut.h"

/* types */
struct ut_keyvalue
{
	int			ukv_type;
	const char *		ukv_key;
	void *			ukv_value;
	struct ut_keyvalue *	ukv_next;
};

struct uri_template
{
	struct ut_keyvalue *	ut_params;
	struct ut_keyvalue *	ut_paramstail;
};

#define	UT_GEN_DELIM(x)		((x) == ':' || \
				 (x) == '/' || \
				 (x) == '?' || \
				 (x) == '#' || \
				 (x) == '[' || \
				 (x) == ']' || \
				 (x) == '@')

#define	UT_SUB_DELIM(x)		((x) == '!' || \
				 (x) == '$' || \
				 (x) == '&' || \
				 (x) == '\'' || \
				 (x) == '(' || \
				 (x) == ')' || \
				 (x) == '*' || \
				 (x) == '+' || \
				 (x) == ',' || \
				 (x) == ';' || \
				 (x) == ';' || \
				 (x) == '=')

#define UT_UNRESERVED(x)	(isalpha(x) || isdigit(x) || \
				 (x) == '-' || \
				 (x) == '.' || \
				 (x) == '_' || \
				 (x) == '~')

#define	UT_RESERVED(x)		(UT_GEN_DELIM(x) || UT_SUB_DELIM(x))

#define UT_OP_RESERVE(x)	((x) == '=' || \
				 (x) == ',' || \
				 (x) == '!' || \
				 (x) == '@' || \
				 (x) == '|')

#define UT_OPERATOR(x)		((x) == '+' || \
				 (x) == '#' || \
				 (x) == '.' || \
				 (x) == '/' || \
				 (x) == ';' || \
				 (x) == '?' || \
				 (x) == '&' || \
				 UT_OP_RESERVE(x))

#define	UT_VARCHAR(x)		(isalpha(*x) || \
				 isdigit(*x) || \
				 (*x) == '_' || \
				 ut_pct_encoded(x))

#define UT_ALLOW_U		1
#define UT_ALLOW_UR		2

/*
**  UT_HEXDIGIT -- hexadecimal digit conversion
**
**  Parameters:
**  	c -- character to convert
**
**  Return value:
**  	Decimal equivalent, or 0 on error.
*/

static int
ut_hexdigit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else
		return 0;
}

/*
**  UT_PCT_ENCODED -- determine whether or not a pct-encoded byte has
**                    been encoutered
**
**  Parameters:
**  	p -- string to scan
** 
**  Return value:
**  	1 iff "p" points to something "pct-encoded"
*/

static int
ut_pct_encoded(const char *p)
{
	assert(p != NULL);

	return (*p == '%' && isxdigit(*(p + 1)) && isxdigit(*(p + 2)));
}

/*
**  UT_VALID_VARNAME -- confirm a valid varname
**
**  Parameters:
**  	s -- string to check
**
**  Return value:
**  	1 iff "s" points to a valid varname
*/

static int
ut_valid_varname(const char *s)
{
	char *p;

	assert(s != NULL);

	if (!UT_VARCHAR(&s[0]))
		return 0;

	for (p = (char *) &s[1]; *p != '\0'; p++)
	{
		if (*p != '.' && !UT_VARCHAR(p))
			return 0;
	}

	return 1;
}

/*
**  UT_FREE -- free a key-value node and its descendents
**
**  Parameters:
**  	kv -- a key-value node
**
**  Return value:
**  	None.
*/

static void
ut_free(struct ut_keyvalue *kv)
{
	assert(kv != NULL);

	if (kv->ukv_type == UT_KEYTYPE_STRING)
	{
		free((void *) kv->ukv_key);
		if (kv->ukv_value != NULL)
			free(kv->ukv_value);

	}
	else if (kv->ukv_type == UT_KEYTYPE_LIST ||
	         kv->ukv_type == UT_KEYTYPE_KEYVALUE)
	{
		struct ut_keyvalue *next;
		struct ut_keyvalue *tmp;

		tmp = kv->ukv_value;
		while (tmp != NULL)
		{
			free((void *) tmp->ukv_key);
			if (tmp->ukv_value != NULL)
				free(tmp->ukv_value);

			next = tmp->ukv_next;
			free(tmp);
			tmp = next;
		}
	}

	free(kv);
}

/*
**  UT_FINDKEY -- locate a key in a URI template handle
**
**  Parameters:
**  	ut -- URITEMP handle
**  	key -- key to find
**
**  Return value:
**  	Pointer to a (struct ut_keyvalue) node, or NULL if not found.
*/

static struct ut_keyvalue *
ut_findkey(URITEMP ut, const char *key)
{
	struct ut_keyvalue *find;

	for (find = ut->ut_params; find != NULL; find = find->ukv_next)
	{
		if (strcasecmp(find->ukv_key, key) == 0)
			return find;
	}

	return NULL;
}

/*
**  UT_APPEND -- append a string, encoding as needed
**
**  Parameters:
**  	ap -- append point
**  	rem -- bytes available at "ap"
**  	allow -- allowed characters
**  	in -- input string
**  	maxlen -- max length (-1 for unbounded)
**
**  Return value:
**  	Count of bytes appended; may exceed "rem" if truncation occurred
*/

static size_t
ut_append(char *ap, size_t rem, int allow, const char *in, int maxlen)
{
	int encode = 0;
	size_t out = 0;
	const char *p;

	assert(ap != NULL);
	assert(allow == UT_ALLOW_U || allow == UT_ALLOW_UR);
	assert(in != NULL);

	for (p = in; *p != '\0'; p++)
	{
		if (allow == UT_ALLOW_U && !UT_UNRESERVED(*p))
			encode = 1;
		else if (allow == UT_ALLOW_UR &&
		         !(UT_UNRESERVED(*p) ||
		           UT_RESERVED(*p) ||
		           ut_pct_encoded(p)))
			encode = 1;
		else
			encode = 0;

		if (encode)
		{
			(void) snprintf(ap, rem, "%%%02X", *p);
			ap += 3;
			rem -= 3;
			out += 3;
		}
		else
		{
			*ap++ = *p;
			rem--;
			out++;

		}

		if (maxlen > 0)
		{
			maxlen--;
			if (maxlen <= 0)
				break;
		}
	}

	return out;
}

/*
**  UT_INIT -- initialize a URI template handle
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

URITEMP
ut_init(void)
{
	struct uri_template *new;

	new = malloc(sizeof *new);

	if (new != NULL)
		memset(new, '\0', sizeof *new);

	return new;
}

/*
**  UT_DESTROY -- release a URI template handle and all allocated resources
**                associated with it
**
**  Parameters:
**  	ut -- URITEMP handle previously allocated by ut_init()
**
**  Return value:
**  	None.
*/

void
ut_destroy(URITEMP ut)
{
	assert(ut != NULL);

	struct ut_keyvalue *kv;
	struct ut_keyvalue *tmp;

	kv = ut->ut_params;
	while (kv != NULL)
	{
		tmp = kv->ukv_next;
		ut_free(kv);
		kv = tmp;
	}

	free(ut);
}

/*
**  UT_KEYVALUE -- set a key-value of some kind inside a URI template
**
**  Parameters:
**  	ut -- URITEMP handle previously returned by ut_init();
**
**  Return value:
**  	0 -- success
**  	!0 -- error
*/

int
ut_keyvalue(URITEMP ut, int type, const char *key, void *value)
{
	int c;
	const char **strings;
	struct ut_keyvalue *kv;
	struct ut_keyvalue *prev;
	struct ut_keyvalue *new;
	struct ut_keyvalue *child;
	struct ut_keyvalue *head;
	struct ut_keyvalue *tail;

	assert(ut != NULL);
	assert(key != NULL);
	assert(value != NULL);
	assert(type == UT_KEYTYPE_STRING ||
	       type == UT_KEYTYPE_LIST ||
	       type == UT_KEYTYPE_KEYVALUE);

	/* see if we have it already */
	prev = NULL;
	kv = ut->ut_params;
	while (kv != NULL)
	{
		if (strcasecmp(key, kv->ukv_key) == 0)
		{
			if (prev != NULL)
			{
				prev->ukv_next = kv->ukv_next;
				if (kv == ut->ut_paramstail)
					ut->ut_paramstail = prev;
				ut_free(kv);
				kv = prev;
			}
			else
			{
				ut->ut_params = kv->ukv_next;
				if (kv == ut->ut_paramstail)
					ut->ut_paramstail = prev;
				ut_free(kv);
				kv = ut->ut_params;
			}

			break;
		}

		prev = kv;
		kv = kv->ukv_next;
	}

	/* store the new one */
	new = malloc(sizeof *new);
	if (new == NULL)
		return -1;

	memset(new, '\0', sizeof *new);
	new->ukv_type = type;

	new->ukv_key = strdup(key);
	if (new->ukv_key == NULL)
	{
		free(new);
		return -1;
	}

	switch (type)
	{
	  case UT_KEYTYPE_STRING:
		new->ukv_value = strdup((char *) value);
		if (new->ukv_value == NULL)
		{
			free((void *) new->ukv_key);
			free(new);
			return -1;
		}
		break;

	  case UT_KEYTYPE_LIST:
		strings = (const char **) value;
		head = NULL;
		tail = NULL;

		for (c = 0; strings[c] != NULL; c++)
		{
			child = malloc(sizeof *child);
			if (child == NULL)
			{
				ut_free(new);
				return -1;
			}

			memset(child, '\0', sizeof *child);

			child->ukv_key = strdup(strings[c]);
			if (child->ukv_key == NULL)
			{
				ut_free(new);
				return -1;
			}

			if (head == NULL)
			{
				head = child;
				tail = child;
			}
			else
			{
				tail->ukv_next = child;
				tail = child;
			}
		}

		new->ukv_value = head;
		break;

	  case UT_KEYTYPE_KEYVALUE:
		strings = (const char **) value;
		head = NULL;
		tail = NULL;

		for (c = 0; strings[c] != NULL; c++)
		{
			if (c % 2 == 0)
			{
				child = malloc(sizeof *child);
				if (child == NULL)
				{
					ut_free(new);
					return -1;
				}

				memset(child, '\0', sizeof *child);

				child->ukv_key = strdup(strings[c]);
				if (child->ukv_key == NULL)
				{
					ut_free(new);
					return -1;
				}
			}
			else
			{
				child->ukv_value = strdup(strings[c]);
				if (child->ukv_value == NULL)
				{
					ut_free(new);
					return -1;
				}
			}

			if (c % 2 == 1)
			{
				if (head == NULL)
				{
					head = child;
					tail = child;
				}
				else
				{
					tail->ukv_next = child;
					tail = child;
				}
			}
		}

		if (c % 2 != 0)
		{
			ut_free(new);
			return -1;
		}

		new->ukv_value = head;
		break;

	  default:
		/* inconceivable! */
		return -1;
	}

	new->ukv_type = type;

	if (ut->ut_params == NULL)
	{
		ut->ut_params = new;
		ut->ut_paramstail = new;
	}
	else
	{
		ut->ut_paramstail->ukv_next = new;
		ut->ut_paramstail = new;
	}

	return 0;
}

/*
**  UT_GENERATE -- generate a URI based on a template and some values
**
**  Parameters:
**  	ut -- URITEMP template previously initialized with ut_init()
**  	template -- input template
**  	out -- output buffer
**  	outlen -- bytes available at "out"
**
**  Return value:
**  	< 0 -- error (see error codes)
**  	otherwise -- length of the generated string; if larger than "outlen",
**   	             truncation has occurred
**
**  Notes:
**  	"out" is always properly terminated.
**
**  	This doesn't support UTF-8 encoding yet.
*/

size_t
ut_generate(URITEMP ut, const char *template, char *out, size_t outlen)
{
	char op;
	unsigned int maxlen;
	int firstout;
	int named;
	int error = UT_ERROR_OK;
	int allow;
	int lsep;
	size_t alen;
	size_t rem;
	size_t olen = 0;
	size_t vlistlen = 0;
	const char *p;
	char *q;
	char *eb;
	char *sep;
	char *first;
	char *ifemp;
	char *v;
	char *ctx;
	char *vlist;
	char *colon;
	char *explode;
	struct ut_keyvalue *ukv;

	assert(ut != NULL);
	assert(template != NULL);
	assert(out != NULL);

	rem = outlen - 1;

	memset(out, '\0', outlen);

	q = out;

	for (p = template; *p != '\0'; p++)
	{
		if (error != 0)
		{
			if (rem > 0)
			{
				*q = *p;
				q++;
				rem--;
			}

			olen++;
			continue;
		}

		if (UT_UNRESERVED(*p) || UT_RESERVED(*p))
		{
			if (rem > 0)
				*q = *p;
			rem--;
			q++;
			olen++;
			continue;
		}
		else if (ut_pct_encoded(p))
		{
			char c;

			c = 16 * ut_hexdigit(*(p + 1)) + ut_hexdigit(*(p + 2));

			*q++ = c;
			olen++;
			rem--;
			p += 2;
			continue;
		}
		else if (*p == '{')
		{
			eb = strchr(p, '}');
			if (eb == NULL)
			{
				*q++ = '{';
				rem--;
				error = UT_ERROR_MALFORMED;
				continue;
			}

			vlistlen = eb - p;

			p++;

			if (*p == '}' || (!UT_OPERATOR(*p) && !UT_VARCHAR(p)))
			{
				*q++ = '{';
				rem--;
				*q++ = *p;
				rem--;
				error = UT_ERROR_MALFORMED;
				continue;
			}

			op = *p;

			firstout = 0;

			switch (op)
			{
			  case '.':
				first = ".";
				sep = ".";
				named = 0;
				ifemp = "";
				allow = UT_ALLOW_U;
				p++;
				vlistlen--;
				break;

			  case '/':
				first = "/";
				sep = "/";
				named = 0;
				ifemp = "";
				allow = UT_ALLOW_U;
				p++;
				vlistlen--;
				break;

			  case ';':
				first = ";";
				sep = ";";
				named = 1;
				ifemp = "";
				allow = UT_ALLOW_U;
				p++;
				vlistlen--;
				break;

			  case '?':
				first = "?";
				sep = "&";
				named = 1;
				ifemp = "=";
				allow = UT_ALLOW_U;
				p++;
				vlistlen--;
				break;

			  case '&':
				first = "&";
				sep = "&";
				named = 1;
				ifemp = "=";
				allow = UT_ALLOW_U;
				p++;
				vlistlen--;
				break;

			  case '#':
				first = "#";
				sep = ",";
				named = 0;
				ifemp = "";
				allow = UT_ALLOW_UR;
				p++;
				vlistlen--;
				break;

			  case '+':
				first = "";
				sep = ",";
				named = 0;
				ifemp = "";
				allow = UT_ALLOW_UR;
				p++;
				vlistlen--;
				break;

			  default:
				first = "";
				sep = ",";
				named = 0;
				ifemp = "";
				allow = UT_ALLOW_U;
				break;
			}

			vlist = strdup(p);
			vlist[vlistlen - 1] = '\0';

			for (v = strtok_r(vlist, ",", &ctx);
			     v != NULL;
			     v = strtok_r(NULL, ",", &ctx))
			{
				colon = strchr(v, ':');
				explode = strchr(v, '*');

				if (colon != NULL)
				{
					*colon = '\0';
					maxlen = atoi(colon + 1);
				}
				else
				{
					maxlen = -1;
				}

				if (explode != NULL)
					*explode = '\0';

				ukv = ut_findkey(ut, v);
				if (ukv == NULL)
					continue;

				if (!ut_valid_varname(v))
					continue;

				if (firstout == 0)
				{
					if (first[0] != '\0')
					{
						if (rem > 0)
						{
							*q++ = first[0];
							rem--;
						}
						olen++;
					}
					firstout = 1;
				}
				else if (sep[0] != '\0')
				{
					if (rem > 0)
					{
						*q++ = sep[0];
						rem--;
					}
					olen++;
				}

				switch (ukv->ukv_type)
				{
				  case UT_KEYTYPE_STRING:
					if (named == 1)
					{
						char *val;

						alen = ut_append(q, rem, allow,
						                 v, -1);
						q += alen;
						if (alen > rem)
							rem = 0;
						else
							rem -= alen;
						olen += alen;

						val = (char *) ukv->ukv_value;
						if (val == NULL ||
						    val[0] == '\0')
						{
							if (ifemp[0] != '\0')
							{
								if (rem > 0)
								{
									*q++ = ifemp[0];
									rem--;
								}

								olen++;
							}
						}
						else
						{
							if (rem > 0)
							{
								*q++ = '=';
								rem--;
							}

							olen++;
						}
					}

					if (colon != NULL)
					{
						alen = ut_append(q, rem, allow,
						                 ukv->ukv_value,
						                 maxlen);

						q += alen;
						if (alen > rem)
							rem = 0;
						else
							rem -= alen;
						olen += alen;
					}
					else
					{
						alen = ut_append(q, rem, allow,
						                 ukv->ukv_value,
						                 -1);

						q += alen;
						if (alen > rem)
							rem = 0;
						else
							rem -= alen;
						olen += alen;
					}

					break;

				  case UT_KEYTYPE_LIST:
					if (explode == NULL)
					{
						struct ut_keyvalue *ikv;

						if (named == 1)
						{
							alen = ut_append(q,
							                 rem,
							                 allow,
							                 v,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							if (ukv->ukv_value == NULL)
							{
								if (ifemp[0] != '\0')
								{
									if (rem > 0)
									{
										*q++ = ifemp[0];
										rem--;
									}
	
									olen++;
								}
							}
							else
							{
								if (rem > 0)
								{
									*q++ = '=';
									rem--;
								}
	
								olen++;
							}
						}

						ikv = ukv->ukv_value;
						lsep = 0;

						while (ikv != NULL)
						{
							if (lsep == 1 &&
							    ikv != ukv->ukv_value)
							{
								if (rem > 0)
								{
									*q++ = ',';
									rem--;
								}
	
								olen++;
							}

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_key,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							ikv = ikv->ukv_next;

							lsep = 1;
						}
					}
					else
					{
						struct ut_keyvalue *ikv;

						ikv = ukv->ukv_value;
						lsep = 0;

						while (ikv != NULL)
						{
							if (lsep == 1 &&
							    ikv != ukv->ukv_value &&
							    sep[0] != '\0')
							{
								if (rem > 0)
								{
									*q++ = sep[0];
									rem--;
								}
	
								olen++;
							}

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_key,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							ikv = ikv->ukv_next;

							lsep = 1;
						}
					}

					break;

				  case UT_KEYTYPE_KEYVALUE:
					if (explode == NULL)
					{
						struct ut_keyvalue *ikv;

						if (named == 1)
						{
							char *val;

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 v,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							val = ukv->ukv_value;
							if (val == NULL)
							{
								if (ifemp[0] != '\0')
								{
									if (rem > 0)
									{
										*q++ = ifemp[0];
										rem--;
									}
	
									olen++;
								}
							}
							else
							{
								if (rem > 0)
								{
									*q++ = '=';
									rem--;
								}
	
								olen++;
							}
						}

						ikv = ukv->ukv_value;
						lsep = 0;

						while (ikv != NULL)
						{
							if (lsep == 1 &&
							    ikv != ukv->ukv_value)
							{
								if (rem > 0)
								{
									*q++ = ',';
									rem--;
								}
	
								olen++;
							}

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_key,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							if (rem > 0)
							{
								*q++ = ',';
								rem--;
							}

							olen++;

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_value,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							lsep = 1;

							ikv = ikv->ukv_next;
						}
					}
					else
					{
						struct ut_keyvalue *ikv;

						ikv = ukv->ukv_value;
						lsep = 0;

						while (ikv != NULL)
						{
							if (lsep == 1 &&
							    ikv != ukv->ukv_value &&
							    sep[0] != '\0')
							{
								if (rem > 0)
								{
									*q++ = sep[0];
									rem--;
								}
	
								olen++;
							}

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_key,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							if (rem > 0)
							{
								*q++ = '=';
								rem--;
							}

							olen++;

							alen = ut_append(q,
							                 rem,
							                 allow,
							                 ikv->ukv_value,
							                 -1);

							q += alen;
							if (alen > rem)
								rem = 0;
							else
								rem -= alen;
							olen += alen;

							lsep = 1;

							ikv = ikv->ukv_next;
						}
					}

					break;
				}
			}

			free(vlist);

			p = eb;
		}
	}

	if (error != UT_ERROR_OK)
		return error;
	else
		return olen;
}

#ifdef TEST
/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

char *listvals[] = { "red", "green", "blue", NULL };
char *keyvals[] = { "semi", ";", "dot", ".", "comma", ",", NULL };

int
main(int argc, char **argv)
{
	int status;
	URITEMP ut;
	char outbuf[4096];

	/* Level 1 examples */
	ut = ut_init();
	assert(ut != NULL);
	
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "var", "value");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "hello", "Hello World!");
	assert(status == 0);

	status = ut_generate(ut, "{var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "value") == 0);
	
	status = ut_generate(ut, "{hello}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "Hello%20World%21") == 0);

	ut_destroy(ut);

	/* Level 2 examples */
	ut = ut_init();
	assert(ut != NULL);

	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "var", "value");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "hello", "Hello World!");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "path", "/foo/bar");
	assert(status == 0);

	status = ut_generate(ut, "{+var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "value") == 0);
	
	status = ut_generate(ut, "{+hello}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "Hello%20World!") == 0);
	
	status = ut_generate(ut, "{+path}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/foo/bar/here") == 0);
	
	status = ut_generate(ut, "here?ref={+path}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "here?ref=/foo/bar") == 0);
	
	status = ut_generate(ut, "X{#var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X#value") == 0);
	
	status = ut_generate(ut, "X{#hello}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X#Hello%20World!") == 0);
	
	ut_destroy(ut);

	/* Level 3 examples */
	ut = ut_init();
	assert(ut != NULL);

	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "var", "value");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "hello", "Hello World!");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "empty", "");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "path", "/foo/bar");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "x", "1024");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "y", "768");
	assert(status == 0);

	status = ut_generate(ut, "map?{x,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "map?1024,768") == 0);

	status = ut_generate(ut, "{x,hello,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "1024,Hello%20World%21,768") == 0);

	status = ut_generate(ut, "{+x,hello,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "1024,Hello%20World!,768") == 0);

	status = ut_generate(ut, "{+path,x}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/foo/bar,1024/here") == 0);

	status = ut_generate(ut, "{#x,hello,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#1024,Hello%20World!,768") == 0);

	status = ut_generate(ut, "{#path,x}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#/foo/bar,1024/here") == 0);

	status = ut_generate(ut, "X{.var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.value") == 0);

	status = ut_generate(ut, "X{.x,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.1024.768") == 0);

	status = ut_generate(ut, "{/var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/value") == 0);

	status = ut_generate(ut, "{/var,x}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/value/1024/here") == 0);

	status = ut_generate(ut, "{;x,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";x=1024;y=768") == 0);

	status = ut_generate(ut, "{;x,y,empty}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";x=1024;y=768;empty") == 0);

	status = ut_generate(ut, "{?x,y}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?x=1024&y=768") == 0);

	status = ut_generate(ut, "{?x,y,empty}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?x=1024&y=768&empty=") == 0);

	status = ut_generate(ut, "?fixed=yes{&x}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?fixed=yes&x=1024") == 0);

	status = ut_generate(ut, "{&x,y,empty}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&x=1024&y=768&empty=") == 0);

	ut_destroy(ut);

	/* Level 4 examples */
	ut = ut_init();
	assert(ut != NULL);

	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "var", "value");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "hello", "Hello World!");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_STRING, "path", "/foo/bar");
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_LIST, "list", listvals);
	assert(status == 0);
	status = ut_keyvalue(ut, UT_KEYTYPE_KEYVALUE, "keys", keyvals);
	assert(status == 0);

	status = ut_generate(ut, "{var:3}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "val") == 0);

	status = ut_generate(ut, "{var:30}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "value") == 0);

	status = ut_generate(ut, "{list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "red,green,blue") == 0);

	status = ut_generate(ut, "{list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "red,green,blue") == 0);

	status = ut_generate(ut, "{keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "{keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "semi=%3B,dot=.,comma=%2C") == 0);

	status = ut_generate(ut, "{+path:6}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/foo/b/here") == 0);

	status = ut_generate(ut, "{+list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "red,green,blue") == 0);

	status = ut_generate(ut, "{+list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "red,green,blue") == 0);

	status = ut_generate(ut, "{+keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "semi,;,dot,.,comma,,") == 0);

	status = ut_generate(ut, "{+keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "semi=;,dot=.,comma=,") == 0);

	status = ut_generate(ut, "{#path:6*}/here", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#/foo/b/here") == 0);

	status = ut_generate(ut, "{#list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#red,green,blue") == 0);

	status = ut_generate(ut, "{#list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#red,green,blue") == 0);

	status = ut_generate(ut, "{#keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#semi,;,dot,.,comma,,") == 0);

	status = ut_generate(ut, "{#keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "#semi=;,dot=.,comma=,") == 0);

	status = ut_generate(ut, "X{.var:3}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.val") == 0);

	status = ut_generate(ut, "X{.list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.red,green,blue") == 0);

	status = ut_generate(ut, "X{.list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.red.green.blue") == 0);

	status = ut_generate(ut, "X{.keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "X{.keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "X.semi=%3B.dot=..comma=%2C") == 0);

	status = ut_generate(ut, "{/var:1,var}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/v/value") == 0);

	status = ut_generate(ut, "{/list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/red,green,blue") == 0);

	status = ut_generate(ut, "{/list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/red/green/blue") == 0);

	status = ut_generate(ut, "{/list*,path:4}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/red/green/blue/%2Ffoo") == 0);

	status = ut_generate(ut, "{/keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "{/keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "/semi=%3B/dot=./comma=%2C") == 0);

	status = ut_generate(ut, "{;hello:5}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";hello=Hello") == 0);

	status = ut_generate(ut, "{;list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";list=red,green,blue") == 0);

	status = ut_generate(ut, "{;list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";red;green;blue") == 0);

	status = ut_generate(ut, "{;keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";keys=semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "{;keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, ";semi=%3B;dot=.;comma=%2C") == 0);

	status = ut_generate(ut, "{?var:3}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?var=val") == 0);

	status = ut_generate(ut, "{?list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?list=red,green,blue") == 0);

	status = ut_generate(ut, "{?list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?red&green&blue") == 0);

	status = ut_generate(ut, "{?keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?keys=semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "{?keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "?semi=%3B&dot=.&comma=%2C") == 0);

	status = ut_generate(ut, "{&var:3}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&var=val") == 0);

	status = ut_generate(ut, "{&list}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&list=red,green,blue") == 0);

	status = ut_generate(ut, "{&list*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&red&green&blue") == 0);

	status = ut_generate(ut, "{&keys}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&keys=semi,%3B,dot,.,comma,%2C") == 0);

	status = ut_generate(ut, "{&keys*}", outbuf, sizeof outbuf);
	assert(status > 0);
	assert(strcmp(outbuf, "&semi=%3B&dot=.&comma=%2C") == 0);

	ut_destroy(ut);

	return 0;
}
#endif /* TEST */
