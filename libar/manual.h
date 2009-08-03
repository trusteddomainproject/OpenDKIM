/*
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
*/

#ifndef _MANUAL_H_
#define _MANUAL_H_

#ifndef lint
static char manual_h_id[] = "@(#)$Id: manual.h,v 1.1 2009/08/03 18:43:10 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* PROTOTYPES */
#ifdef AF_INET6
extern int ar_res_parse(int *, struct sockaddr_storage *, int *, int *);
#else /* AF_INET6 */
extern int ar_res_parse(int *, struct sockaddr_in *, int *, int *);
#endif /* AF_INET6 */

#endif /* ! _MANUAL_H_ */
