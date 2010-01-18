/*
**  Copyright (c) 2008, 2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, The OpenDKIM Project.  All rights reserved.
**
**  $Id: opendkim-crypto.c,v 1.6 2010/01/18 22:44:24 cm-msk Exp $
*/

#ifndef lint
static char opendkim_crypto_c_id[] = "@(#)$Id: opendkim-crypto.c,v 1.6 2010/01/18 22:44:24 cm-msk Exp $";
#endif /* !lint */

/* system includes */
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>

/* openssl includes */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

/* opendkim includes */
#include "opendkim-crypto.h"
#include "opendkim.h"

/* globals */
static _Bool crypto_init_done = FALSE;
static pthread_mutex_t id_lock;
static pthread_key_t id_key;
static unsigned int nmutexes = 0;
static unsigned long threadid = 0L;
static pthread_mutex_t *mutexes = NULL;

/*
**  DKIMF_CRYPTO_LOCK_CALLBACK -- locking callback for libcrypto
**
**  Parameters:
**  	mode -- lock mode (request from libcrypto)
**  	idx -- lock index for this request
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
dkimf_crypto_lock_callback(int mode, int idx,
                           /* UNUSED */ const char *file,
                           /* UNUSED */ int line)
{
	int status;

	if ((mode & CRYPTO_LOCK) != 0)
		status = pthread_mutex_lock(&mutexes[idx]);
	else
		status = pthread_mutex_unlock(&mutexes[idx]);

	assert(status == 0);
}

/*
**  DKIMF_CRYPTO_GET_ID -- generate/retrieve thread ID
**
**  Parameters:
**
**  Return value:
**
*/

static unsigned long
dkimf_crypto_get_id(void)
{
	unsigned long *id;

	id = pthread_getspecific(id_key);
	if (id == NULL)
	{
		id = (unsigned long *) malloc(sizeof *id);
		assert(pthread_mutex_lock(&id_lock) == 0);
		threadid++;
		*id = threadid;
		assert(pthread_mutex_unlock(&id_lock) == 0);
		assert(pthread_setspecific(id_key, id) == 0);
	}

	return *id;
}

/*
**  DKIMF_CRYPTO_FREE_ID -- destroy thread ID
**
**  Parameters:
**  	ptr -- pointer to be destroyed
**
**  Return value:
**  	None.
*/

static void
dkimf_crypto_free_id(void *ptr)
{
	/*
	**  Trick dkimf_crypto_get_id(); the thread-specific pointer has
	**  already been cleared at this point, but dkimf_crypto_get_id()
	**  may be called by ERR_remove_state() which will then allocate a
	**  new thread pointer if the thread-specific pointer is NULL.  This
	**  means a memory leak of thread IDs and, on Solaris, an infinite loop
	**  because the destructor (indirectly) re-sets the thread-specific
	**  pointer to something not NULL.  See pthread_key_create(3).
	*/

	assert(pthread_setspecific(id_key, ptr) == 0);

	ERR_remove_state(0);
	if (ptr != NULL)
		free(ptr);

	/*
	**  Now we can actually clear it for real.
	*/

	assert(pthread_setspecific(id_key, NULL) == 0);
}

/*
**  DKIMF_CRYPTO_DYN_CREATE -- dynamically create a mutex
**
**  Parameters:
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	Pointer to the new mutex.
*/

static struct CRYPTO_dynlock_value *
dkimf_crypto_dyn_create(/* UNUSED */ const char *file,
                        /* UNUSED */ int line)
{
	int err;
	pthread_mutex_t *new;

	new = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
	if (new == NULL)
		return NULL;

	err = pthread_mutex_init(new, NULL);
	if (err != 0)
	{
		free(new);
		return NULL;
	}

	return (void *) new;
}

/*
**  DKIMF_CRYPTO_DYN_DESTROY -- destroy a dynamic mutex
**
**  Parameters:
**  	mutex -- pointer to the mutex to destroy
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
dkimf_crypto_dyn_destroy(struct CRYPTO_dynlock_value *lock,
                         /* UNUSED */ const char *file,
                         /* UNUSED */ int line)
{
	assert(lock != NULL);

	pthread_mutex_destroy((pthread_mutex_t *) lock);

	free(lock);
}

/*
**  DKIMF_CRYPTO_DYN_LOCK -- lock/unlock a dynamic mutex
**
**  Parameters:
**  	mode -- lock mode (request from libcrypto)
**  	mutex -- pointer to the mutex to lock/unlock
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
dkimf_crypto_dyn_lock(int mode, struct CRYPTO_dynlock_value *lock,
                      /* UNUSED */ const char *file,
                      /* UNUSED */ int line)
{
	int status;

	assert(lock != NULL);

	if ((mode & CRYPTO_LOCK) != 0)
		status = pthread_mutex_lock((pthread_mutex_t *) lock);
	else
		status = pthread_mutex_unlock((pthread_mutex_t *) lock);

	assert(status == 0);
}

/*
**  DKIMF_CRYPTO_INIT -- set up openssl dependencies
**
**  Parameters:
**  	None.
**
**  Return value:
**  	0 -- success
**  	!0 -- an error code (a la errno)
*/

int
dkimf_crypto_init(void)
{
	int c;
	int n;
	int status;

	n = CRYPTO_num_locks();
	mutexes = (pthread_mutex_t *) malloc(n * sizeof(pthread_mutex_t));
	if (mutexes == NULL)
		return errno;

	for (c = 0; c < n; c++)
	{
		status = pthread_mutex_init(&mutexes[c], NULL);
		if (status != 0)
			return status;
	}

	status = pthread_mutex_init(&id_lock, NULL);
	if (status != 0)
		return status;

	nmutexes = n;

	status = pthread_key_create(&id_key, &dkimf_crypto_free_id);
	if (status != 0)
		return status;

	SSL_load_error_strings();
	SSL_library_init();
	ERR_load_crypto_strings();

	CRYPTO_set_id_callback(&dkimf_crypto_get_id);
	CRYPTO_set_locking_callback(&dkimf_crypto_lock_callback);
	CRYPTO_set_dynlock_create_callback(&dkimf_crypto_dyn_create);
	CRYPTO_set_dynlock_lock_callback(&dkimf_crypto_dyn_lock);
	CRYPTO_set_dynlock_destroy_callback(&dkimf_crypto_dyn_destroy);

#ifdef USE_OPENSSL_ENGINE
	if (!SSL_set_engine(NULL))
		return EINVAL;
#endif /* USE_OPENSSL_ENGINE */

	crypto_init_done = TRUE;

	return 0;
}

/*
**  DKIMF_CRYPTO_FREE -- tear down openssl dependencies
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dkimf_crypto_free(void)
{
	if (crypto_init_done)
	{
		if (nmutexes > 0)
		{
			unsigned int c;

			for (c = 0; c < nmutexes; c++)
				pthread_mutex_destroy(&mutexes[c]);

			free(mutexes);
			mutexes = NULL;
			nmutexes = 0;
		}

		CONF_modules_free();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		ERR_remove_state(0);

		crypto_init_done = FALSE;
	}
}
