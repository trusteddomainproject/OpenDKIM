/*
**  Copyright (c) 2011, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _AR_SOCKET_H_
#define _AR_SOCKET_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/time.h>

/* data types */
struct ar_socket_set;
typedef struct ar_socket_set * AR_SOCKET_SET;

/* event types */
#define	AR_SOCKET_EVENT_READ		0x01
#define	AR_SOCKET_EVENT_WRITE		0x02
#define	AR_SOCKET_EVENT_EXCEPTION	0x04

/* prototypes */
extern int ar_socket_add(AR_SOCKET_SET, int, unsigned int);
extern int ar_socket_check(AR_SOCKET_SET, int, unsigned int);
extern void ar_socket_free(AR_SOCKET_SET);
extern AR_SOCKET_SET ar_socket_init(unsigned int);
extern void ar_socket_reset(AR_SOCKET_SET);
extern int ar_socket_wait(AR_SOCKET_SET, int);

#endif /* ! _AR_SOCKET_H_ */
