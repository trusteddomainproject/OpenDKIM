/*
**  Copyright (c) 2011, 2012, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _UT_H_
#define _UT_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* types */
struct uri_template;
typedef struct uri_template * URITEMP;

#define	UT_KEYTYPE_STRING	1
#define	UT_KEYTYPE_LIST		2
#define	UT_KEYTYPE_KEYVALUE	3

#define	UT_ERROR_OK		0
#define	UT_ERROR_MALFORMED	(-1)

/* prototypes */
extern URITEMP ut_init(void);
extern void ut_destroy(URITEMP);
extern int ut_keyvalue(URITEMP, int, const char *, void *);
extern size_t ut_generate(URITEMP, const char *, char *, size_t);

#endif /* ! _UT_H_ */
