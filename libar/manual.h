/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _MANUAL_H_
#define _MANUAL_H_

#ifndef lint
static char manual_h_id[] = "@(#)$Id: manual.h,v 1.3 2009/10/27 06:38:00 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

/* PROTOTYPES */
#ifdef AF_INET6
extern int ar_res_parse(int *, struct sockaddr_storage *, int *, time_t *);
#else /* AF_INET6 */
extern int ar_res_parse(int *, struct sockaddr_in *, int *, time_t *);
#endif /* AF_INET6 */

#endif /* ! _MANUAL_H_ */
