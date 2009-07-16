/*
**  Copyright (c) 2005, 2007, 2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef lint
static char rfc2822_c_id[] = "@(#)$Id: rfc2822.c,v 1.1 2009/07/16 19:12:04 cm-msk Exp $";
#endif /* !lint */

/* system inludes */
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

/* types */
typedef unsigned long cmap_elem_type;

/* symbolic names */
#define RFC2822_OK 			0 	/* success */
#define RFC2822_ERR_PUNBALANCED		1	/* unbalanced parentheses */
#define RFC2822_ERR_QUNBALANCED		2	/* unbalanced quotes */
#define RFC2822_ERR_SUNBALANCED	 	3	/* unbalanced sq. brackets */

/* a bitmap for the "specials" character class */
#define	CMAP_NBITS	 	(sizeof(cmap_elem_type) * CHAR_BIT)
#define	CMAP_NELEMS	  	((1 + UCHAR_MAX) / CMAP_NBITS)
#define	CMAP_INDEX(i)		((unsigned char)(i) / CMAP_NBITS)
#define	CMAP_BIT(i)  		(1L << (unsigned char)(i) % CMAP_NBITS)
#define	CMAP_TST(ar, c)    	((ar)[CMAP_INDEX(c)] &  CMAP_BIT(c))
#define	CMAP_SET(ar, c)    	((ar)[CMAP_INDEX(c)] |= CMAP_BIT(c))

static unsigned char const SPECIALS[] = "<>@,;:\\\"/[]?=";

#ifdef RFC2822_TEST
/*
**  UNESCAPE -- remove escape characters from a string
**
**  Parameters:
**  	s -- the string to be unescaped
**
**  Return value:
**  	s.
*/

static char *
unescape(char *s)
{
	char 		*w;
	char const 	*r, *p, *e;

	if (s == NULL)
		return NULL;

	r = w = s;
	e = s + strlen(s);

	while ((p = memchr(r, '\\', e - s)) != NULL)
	{
		if (p > s)
		{
			if (r != w)
				memmove(w, r, p - r);
			w += p - r;
		}

		if (p[1] == '\0')
		{
			r = p + 1;
		}
		else
		{
			*w++ = p[1];
			r = p + 2;
		}
	}

	if (r > w)
	{
		if (e > r)
		{
			memmove(w, r, e - r);
			w += e - r;
		}
		*w = '\0';
	}

	return s;
}
#endif /* RFC2822_TEST */

/*
**  MATCHING_PAREN -- return the location past matching opposite parentheses
**
**  Parameters:
**  	s -- start of string to be processed
**  	e -- end of string to be processed
**  	open_paren -- open parenthesis character
**  	close_paren -- close parenthesis character
**
**  Return value:
**  	Location of the final close parenthesis character in the string.
**  	For example, given "xxx((yyyy)zz)aaaa", would return the location
**  	of the second ")".  There may be more beyond that, but at that point
**  	everything is balanced.
*/

static char *
matching_paren(char *s, char *e, int open_paren, int close_paren)
{
	int 		paren = 1;

	for (; s < e; s++)
	{
		if (*s == close_paren)
		{
			if (--paren == 0)
				break;
		}
		else if (*s == open_paren)
		{
			paren++;
		}
		else if (*s == '\\')
		{
			if (s[1] != '\0')
				s++;
		}
	}

	return s;
}

/*
**  RFC2822_FIRST_SPECIAL -- find the first RFC2822 "special" character
**
**  Parameters:
**  	p -- input string
**  	e -- end of input string
**  	special_out -- pointer to the first special character found
**
**  Return value:
**  	0 on success, or an RFC2822_ERR_* on failure.
*/

static int
rfc2822_first_special(char *p, char *e, char **special_out)
{
	size_t		i;
	cmap_elem_type	is_special[CMAP_NELEMS] = { 0 };
	char		*at_ptr = NULL;

	/* set up special finder */
	for (i = 0; SPECIALS[i] != '\0'; i++)
		CMAP_SET(is_special, SPECIALS[i]);

	for (; p < e && *p != '\0'; p++)
	{
		/* skip white space between tokens */
		while (p < e && (*p == '(' ||
		                 (isascii((unsigned char) *p) &&
		                  isspace((unsigned char) *p))))
		{
			if (*p != '(')
			{
				p++;
			}
			else
			{
				p = matching_paren(p + 1, e, '(', ')');
				if (*p == '\0')
					return RFC2822_ERR_PUNBALANCED;
				else
					p++;
			}
		}

		if (*p == '\0')
			break;

		if (*p == '"')
		{
			p = matching_paren(p + 1, e, '\0', '"');
			if (*p == '\0')
				return RFC2822_ERR_QUNBALANCED;
		}
		else if (*p == '[')
		{
			p = matching_paren(p + 1, e, '\0', ']');
			if (*p == '\0')
				return RFC2822_ERR_SUNBALANCED;
		}
		else if (CMAP_TST(is_special, *p))
		{
			if (*p == '<')
			{
				*special_out = p;
				return 0;
			}
			else if (*p == ':' || *p == ';' || *p == ',')
			{
				if (at_ptr != NULL)
					*special_out = at_ptr;
				else
					*special_out = p;
				return 0; 
			}
			else if (*p == '@')
			{
				at_ptr = p;
			}
		}
		else
		{
			while (*p != '\0' &&
			       !CMAP_TST(is_special, *p) &&
			       (!isascii(*p) ||
			        !isspace((unsigned char) *p)) &&
			       *p != '(')
				p++;
			p--;
		}
	}

	*special_out = p;
	return 0;
}

/*
**  RFC2822_TOKEN -- find the next token
**
**  Parameters:
**  	s -- start of input string
**  	e -- end of input string
**  	type_out -- type of token (returned)
**  	start_out -- start of token (returned)
**  	end_out -- start of token (returned)
**  	uncommented_whitespace -- set to TRUE if uncommented whitespace is
**  	                          discovered (returned)
**
**  Return value:
**  	0 on success, or an RFC2822_ERR_* on failure.
*/

static int
rfc2822_token(char *s, char *e, int *type_out, char **start_out,
              char **end_out, int *uncommented_whitespace)
{
	char *p;
	int err = 0;
	size_t i;
	int token_type;
	cmap_elem_type is_special[CMAP_NELEMS] = { 0 };
	char *token_start, *token_end;

	*start_out = NULL;
	*end_out   = NULL;
	*type_out  = 0;

	err = 0;

	/* set up special finder */
	for (i = 0; SPECIALS[i] != '\0'; i++)
		CMAP_SET(is_special, SPECIALS[i]);

	p = s;

	/* skip white space between tokens */
	while (p < e && (*p == '(' ||
	                 (isascii((unsigned char) *p) &&
	                  isspace((unsigned char) *p))))
	{
		if (*p != '(')
		{
			*uncommented_whitespace = 1;
			p++;
		}
		else
		{
			p = matching_paren(p + 1, e, '(', ')');
			if (*p == '\0')
				return RFC2822_ERR_PUNBALANCED;
			else
				p++;
		}
	}

	if (p >= e || *p == '\0')
		return 0;

	/* our new token starts here */
	token_start = p;

	/* fill in the token contents and type */
	if (*p == '"')
	{
		token_end = matching_paren(p + 1, e, '\0', '"');
		token_type = '"';
		if (*token_end != '\0')
			token_end++;
		else
			err = RFC2822_ERR_QUNBALANCED;
	}
	else if (*p == '[')
	{
		token_end = p = matching_paren(p + 1, e, '\0', ']');
		token_type = '[';
		if (*token_end != '\0')
			token_end++;
		else
			err = RFC2822_ERR_SUNBALANCED;
	}
	else if (CMAP_TST(is_special, *p))
	{
		token_end  = p + 1;
		token_type = *p;
	}
	else
	{
		while (p < e && *p != '\0' && !CMAP_TST(is_special, *p) &&
		       (!isascii(*p) || !isspace((unsigned char) *p)) &&
		       *p != '(')
			p++;

		token_end = p;
		token_type = 'x';
	}

	*start_out = token_start;
	*end_out   = token_end;
	*type_out  = token_type;

	return err;
}

/*
**  RFC2822_MAILBOX_SPLIT -- extract the local-part and hostname from an
**                           RFC2822 header, e.g. "From:"
**
**  Parameters:
**  	line -- input line
**  	user_out -- pointer to "local-part" (returned)
**  	domain_out -- pointer to hostname (returned)
**
**  Return value:
**  	0 on success, or an RFC2822_ERR_* on failure.
**
**  Notes:
**  	Input string is modified.
*/

int
rfc2822_mailbox_split(char *line, char **user_out, char **domain_out)
{
	int type;
	int ws;
	int err;
	char *e, *special;
	char *tok_s, *tok_e;
	char *w;

	*user_out = NULL;
	*domain_out = NULL;

	err = 0;
	w = line;
	e = line + strlen(line);
	ws = 0;

	for (;;)
	{
		err = rfc2822_first_special(line, e, &special);
		if (err != 0)
			return err;
		
		/* given the construct we're looking at, do the right thing */
		switch (*special)
		{
		  case '<':
			/* display name <address> */
			line = special + 1;
			for (;;)
			{
				err = rfc2822_token(line, e, &type, &tok_s,
				                    &tok_e, &ws);
				if (err != 0)
					return err;

				if (type == '>' || type == '\0')
				{
					*w = '\0';
					return 0;
				}
				else if (type == '@')
				{
					*w++ = '\0';
					*domain_out = w;
				}
				else if (type == ',' || type == ':')
				{
					/* source route punctuation */
					*user_out = NULL;
					*domain_out = NULL;
				}
				else
				{
					if (*user_out == NULL)
						*user_out = w;
					memmove(w, tok_s, tok_e - tok_s);
					w += tok_e - tok_s;
				}
				line = tok_e;
			}
			return 0;

		  case ';':
		  case ':':
		  case ',':
			/* skip a group name or result */
		  	line = special + 1;
			break;

		  default:
			/* (display name) addr(display name)ess */
			ws = 0;
			for (;;)
			{
				err = rfc2822_token(line, e, &type, &tok_s,
				                    &tok_e, &ws);
				if (err != 0)
					return err;

				if (type == '\0' ||  type == ',' || type == ';')
				{
					*w = '\0';
					break;
				}
				else if (type == '@')
				{
					*w++ = '\0';
					*domain_out = w;
					ws = 0;
				}
				else
				{

					if (*user_out == NULL)
						*user_out = w;
					else if (type == 'x' && ws == 1)
						*w++ = ' ';

					memmove(w, tok_s, tok_e - tok_s);
					w += tok_e - tok_s;

					ws = 0;
				}

				line = tok_e;
			}
			return 0;
		}
	}

	return err;
}

#ifdef RFC2822_TEST
int
main(int argc, char **argv)
{
	int err;
	char *domain, *user;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s mailheader\n", argv[0]);
		exit(64);
	}

	err = rfc2822_mailbox_split(argv[1], &user, &domain);

	if (err)
	{
		printf("error %d\n", err);
	}
	else
	{
		printf("user: '%s'\ndomain: '%s'\n", 
			user ? unescape(user) : "null",
			domain ? unescape(domain) : "null");
	}

	return 0;
}
#endif /* RFC2822_TEST */
