/*
 * Phoenix-RTOS
 *
 * POSIX server - semaphores
 *
 * Copyright 2026 Phoenix Systems
 * Author: Michal Lach, Ziemowit Leszczynski
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/list.h>
#include <sys/ioctl.h>
#include <sys/minmax.h>
#include <phoenix/semaphore.h>

#include "posixsrv_private.h"

#if 0
#define SEMAPHORE_TRACE(str, ...) printf("posixsrv semaphore: " str "\n", ##__VA_ARGS__);
#else
#define SEMAPHORE_TRACE(str, ...)
#endif


enum {
	semaphore_downBlock = 0, /* SEM_DOWN: block until posted */
	semaphore_downTry,       /* SEM_DOWN_TRY: never block */
	semaphore_downTimed      /* SEM_DOWN_TIMEOUT: block until posted or deadline passes */
};


static struct {
	handle_t lock;
	/* live semaphores, bounded by SEM_NSEMS_MAX */
	unsigned int count;
} semaphore_common;


typedef struct {
	object_t object;

	/* holds the full /dev path */
	char name[sizeof(SEMAPHORE_PATH) + NAME_MAX];

	handle_t lock;
	request_t *queue;

	unsigned int value;

	/*
	 * Guarded by lock. POSIX requires sem_unlink() to remove the name at once
	 * but to destroy the semaphore only after the last sem_close(), so the
	 * object outlives its /dev node whenever handles are still open.
	 */
	unsigned int opens;
	bool unlinked;
	bool linkDropped;
} shared_semaphore_t;


/*
 * Inserts `request` into the wait queue, highest priority first and FIFO among
 * equal priorities. Must be called with sem->lock held.
 */
static void _semaphore_enqueue(shared_semaphore_t *sem, request_t *request)
{
	request_t *it;

	if (sem->queue == NULL) {
		LIST_ADD(&sem->queue, request);
		return;
	}

	/* stopping on higher priority leaves equal priorities in arrival order */
	it = sem->queue;
	do {
		if (request->msg.priority < it->msg.priority) {
			break;
		}
		it = it->next;
	} while (it != sem->queue);

	request->next = it;
	request->prev = it->prev;
	it->prev->next = request;
	it->prev = request;

	if (request->msg.priority < sem->queue->msg.priority) {
		sem->queue = request;
	}
}


/*
 * Reserves one of the SEM_NSEMS_MAX slots. Reserving before the object exists
 * keeps two concurrent creates from both passing the check. The reservation is
 * handed to the object once it is created, and released by semaphore_release().
 */
static int semaphore_slotGet(void)
{
	int ret;

	mutexLock(semaphore_common.lock);
	if (semaphore_common.count >= SEM_NSEMS_MAX) {
		ret = -ENOSPC;
	}
	else {
		semaphore_common.count++;
		ret = EOK;
	}
	mutexUnlock(semaphore_common.lock);

	return ret;
}


static void semaphore_slotPut(void)
{
	mutexLock(semaphore_common.lock);
	if (semaphore_common.count > 0) {
		semaphore_common.count--;
	}
	mutexUnlock(semaphore_common.lock);
}


/*
 * `deadlineUs` is the absolute CLOCK_REALTIME deadline in microseconds, used
 * only by semaphore_downTimed.
 */
static int semaphore_down(shared_semaphore_t *sem, request_t *request, int mode, time_t deadlineUs)
{
	int ret;
	time_t now, offs;

	mutexLock(sem->lock);

	if (sem->value > 0) {
		sem->value--;
		ret = EOK;
	}
	else if (mode == semaphore_downTry) {
		ret = -EAGAIN;
	}
	else if (mode == semaphore_downBlock) {
		_semaphore_enqueue(sem, request);
		ret = -EBUSY;
	}
	else {
		gettime(&now, &offs);

		if (deadlineUs <= (now + offs)) {
			ret = -ETIMEDOUT;
		}
		else {
			_semaphore_enqueue(sem, request);

			/*
			 * gettime() reports realtime as raw + offs and the timeout thread
			 * compares against raw, so drop the offset.
			 */
			rq_timeoutAt(request, deadlineUs - offs);
			ret = -EBUSY;
		}
	}

	mutexUnlock(sem->lock);

	return ret;
}


static int semaphore_up(shared_semaphore_t *sem, request_t *request)
{
	int ret = EOK;
	request_t *waiter, *granted = NULL;
	unsigned int newval = 0;
	bool overflow;

	mutexLock(sem->lock);

	while (sem->queue != NULL) {
		waiter = sem->queue;
		LIST_REMOVE(&sem->queue, waiter);
		if (rq_timeoutCancel(waiter) != 0) {
			granted = waiter;
			break;
		}
	}

	if (granted != NULL) {
		rq_setResponse(granted, EOK);
		rq_wakeup(granted);
	}
	else {
		overflow = __builtin_add_overflow(sem->value, 1, &newval);
		if (overflow || newval > SEM_VALUE_MAX) {
			ret = -EOVERFLOW;
		}
		else {
			sem->value = newval;
		}
	}

	mutexUnlock(sem->lock);

	return ret;
}


static void semaphore_getValue(shared_semaphore_t *sem, request_t *request)
{
	unsigned int value = 0;

	mutexLock(sem->lock);
	value = sem->value;
	mutexUnlock(sem->lock);

	ioctl_setResponse(&request->msg, SEM_GETVALUE, EOK, &value);
}


static request_t *semaphore_open_op(object_t *object, request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;

	SEMAPHORE_TRACE("open(%s): refs: %d", sem->name, object->refs);

	mutexLock(sem->lock);
	sem->opens++;
	mutexUnlock(sem->lock);

	posixsrv_object_ref(object);
	rq_setResponse(request, EOK);
	return request;
}


static request_t *semaphore_close_op(object_t *object, request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;
	bool last;

	SEMAPHORE_TRACE("close(%s) refs: %d", sem->name, object->refs);

	mutexLock(sem->lock);
	if (sem->opens > 0) {
		sem->opens--;
	}
	last = sem->unlinked && (sem->opens == 0) && !sem->linkDropped;
	if (last) {
		sem->linkDropped = true;
	}
	mutexUnlock(sem->lock);

	if (last) {
		/* Unlinked earlier and this was the last handle - drop the link reference */
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}

	/* balances the reference semaphore_open_op() takes for this handle */
	posixsrv_object_put(object);

	rq_setResponse(request, EOK);
	return request;
}


/*
 * Latches `unlinked` and claims the link reference when nothing holds
 * the semaphore open. Returns true when the caller now owns that reference
 * and must release it,  otherwise the last semaphore_close_op() will.
 */
static bool semaphore_markUnlinked(shared_semaphore_t *sem)
{
	bool last;

	mutexLock(sem->lock);
	sem->unlinked = true;
	last = (sem->opens == 0) && !sem->linkDropped;
	if (last) {
		sem->linkDropped = true;
	}
	mutexUnlock(sem->lock);

	return last;
}


static request_t *semaphore_destroy_op(object_t *object, request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;
	bool unlinked;
	int ret;

	SEMAPHORE_TRACE("destroy: %s", sem->name);

	mutexLock(sem->lock);
	unlinked = sem->unlinked;
	mutexUnlock(sem->lock);

	if (unlinked) {
		/* The name is already gone */
		rq_setResponse(request, -ENOENT);
		return request;
	}

	/*
	 * Nothing is latched until the node is actually gone: on failure the semaphore
	 * must stay reachable by name, and sem_unlink() must be able to report why.
	 */
	ret = destroy_dev(sem->name);
	if (ret < 0) {
		rq_setResponse(request, (ret == -ENODEV) ? -ENOENT : ret);
		return request;
	}

	if (semaphore_markUnlinked(sem)) {
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}

	rq_setResponse(request, EOK);
	return request;
}


static request_t *semaphore_unlink_op(object_t *object, request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;

	SEMAPHORE_TRACE("unlink: %s", sem->name);

	/*
	 * posix_unlink() messages the directory owner first, so by the time this
	 * arrives the /dev entry is already gone - only the object side is left.
	 * Without this handler the message would be answered -EINVAL and unlink()
	 * would remove the entry and then report failure, orphaning the object.
	 */
	if (semaphore_markUnlinked(sem)) {
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}

	rq_setResponse(request, EOK);
	return request;
}


static void semaphore_release(object_t *object)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;
	request_t *waiter;

	SEMAPHORE_TRACE("release(%s)", sem->name);

	/*
	 * This handles a case when semaphore is scheduled for deletion but
	 * still has waiters. Should not happen, but better to define the
	 * behaviour, rather than leaving threads dangling.
	 */
	while (sem->queue != NULL) {
		waiter = sem->queue;
		LIST_REMOVE(&sem->queue, waiter);
		if (rq_timeoutCancel(waiter) != 0) {
			rq_setResponse(waiter, -EINVAL);
			rq_wakeup(waiter);
		}
	}

	resourceDestroy(sem->lock);
	free(object);

	semaphore_slotPut();
}


static request_t *semaphore_devctl_op(object_t *object, request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)object;
	unsigned long cmd;
	struct timespec abstime;
	time_t deadline = -1;
	int ret = EOK;
	const void *in;

	SEMAPHORE_TRACE("devctl(%s)", sem->name);

	in = ioctl_unpack(&request->msg, &cmd, NULL);
	switch (cmd) {
		case SEM_UP:
			SEMAPHORE_TRACE("devctl(%s): UP", sem->name);
			ret = semaphore_up(sem, request);
			break;

		case SEM_DOWN_TRY:
			SEMAPHORE_TRACE("devctl(%s): DOWN_TRY", sem->name);
			ret = semaphore_down(sem, request, semaphore_downTry, 0);
			break;

		case SEM_DOWN_TIMEOUT:
			memcpy(&abstime, in, sizeof(abstime));

			/*
			 * TODO: the deadline is carried as a timespec but the request
			 * timeout is in microseconds, so a tv_sec beyond TIME_T_MAX / 1000000
			 * overflows here. Rework rq_timeout*() to take a timespec, then this
			 * conversion goes away. Rounds up, so the wait never ends early.
			 */
			deadline = abstime.tv_sec * 1000000 + (abstime.tv_nsec + 999) / 1000;

			SEMAPHORE_TRACE("devctl(%s): DOWN_TIMEOUT %lld", sem->name, deadline);
			ret = semaphore_down(sem, request, semaphore_downTimed, deadline);
			break;

		case SEM_DOWN:
			SEMAPHORE_TRACE("devctl(%s): DOWN", sem->name);
			ret = semaphore_down(sem, request, semaphore_downBlock, 0);
			break;

		case SEM_GETVALUE:
			SEMAPHORE_TRACE("devctl(%s): GETVALUE", sem->name);
			semaphore_getValue(sem, request);
			break;

		default:
			ret = -EINVAL;
	}

	SEMAPHORE_TRACE("devctl(%s): returns %d", sem->name, ret);

	if (ret == -EBUSY) {
		return NULL; /* blocking on timeout */
	}

	if (cmd != SEM_GETVALUE) {
		rq_setResponse(request, ret);
	}

	return request;
}


static void semaphore_timeout(request_t *request)
{
	shared_semaphore_t *sem = (shared_semaphore_t *)request->object;

	SEMAPHORE_TRACE("timeout(%s)", sem->name);

	mutexLock(sem->lock);
	/*
	 * A waker may have unlinked the request before losing the race for it in
	 * rq_timeoutCancel(). LIST_REMOVE() NULLs both links, so this tells the two
	 * cases apart.
	 */
	if (request->next != NULL) {
		LIST_REMOVE(&sem->queue, request);
	}
	mutexUnlock(sem->lock);

	rq_setResponse(request, -ETIMEDOUT);
	rq_wakeup(request);
}


static const operations_t semaphore_ops = {
	.open = semaphore_open_op,
	.close = semaphore_close_op,
	.devctl = semaphore_devctl_op,
	.timeout = semaphore_timeout,
	.destroy = semaphore_destroy_op,
	.unlink = semaphore_unlink_op,
	.release = semaphore_release,
};


static int semaphore_create(const char *name, unsigned int value, int mode, int *id)
{
	int len, ret;
	shared_semaphore_t *sem;

	if (name == NULL || value > SEM_VALUE_MAX) {
		return -EINVAL;
	}

	if (*name == '/') {
		name++;
	}

	if (*name == '\0' || strchr((char *)name, '/') != NULL) {
		return -EINVAL;
	}

	ret = semaphore_slotGet();
	if (ret != EOK) {
		return ret;
	}

	sem = malloc(sizeof(*sem));
	if (sem == NULL) {
		semaphore_slotPut();
		return -ENOMEM;
	}

	len = snprintf(sem->name, sizeof(sem->name), "%s%s", SEMAPHORE_PATH, name);
	if (len < 0 || (size_t)len >= sizeof(sem->name)) {
		free(sem);
		semaphore_slotPut();
		return -ENAMETOOLONG;
	}

	if (mutexCreate(&sem->lock) < 0) {
		free(sem);
		semaphore_slotPut();
		return -ENOMEM;
	}

	/*
	 * From here the reservation belongs to the object. Every path below ends
	 * in semaphore_release(), which returns it.
	 */

	sem->value = value;
	sem->queue = NULL;
	sem->opens = 0;
	sem->unlinked = false;
	sem->linkDropped = false;

	posixsrv_object_create(&sem->object, &semaphore_ops);
	if (posixsrv_object_link(&sem->object, sem->name) < 0) {
		posixsrv_object_destroy(&sem->object);
		posixsrv_object_put(&sem->object);
		return -EEXIST;
	}

	*id = posixsrv_object_id(&sem->object);

	/*
	 * TODO: apply `mode` to the node. create_dev() takes no mode argument,
	 * so the requested permissions are dropped here.
	 */
	(void)mode;

	/*
	 * The linked object keeps the initial reference. It is dropped by
	 * semaphore_destroy_op() or by the last semaphore_close_op() after an unlink.
	 */

	return EOK;
}


static request_t *semaphore_create_op(object_t *srv, request_t *request)
{
	int id = 0, ret;

	ret = semaphore_create(request->msg.i.data, (unsigned int)request->msg.i.create.type, request->msg.i.create.mode, &id);

	SEMAPHORE_TRACE("create: id = %d, ret = %d", id, ret);

	rq_setResponse(request, ret);
	if (ret == EOK) {
		request->msg.o.create.oid.port = posixsrv_port();
		request->msg.o.create.oid.id = id;
	}

	return request;
}


const static operations_t semaphore_control_ops = {
	.create = semaphore_create_op,
};


int semaphore_init(void)
{
	object_t *object;
	int err;

	object = malloc(sizeof(*object));
	if (object == NULL) {
		return -ENOMEM;
	}

	semaphore_common.count = 0;

	if (mutexCreate(&semaphore_common.lock) < 0) {
		free(object);
		return -ENOMEM;
	}

	err = mkdir(SEMAPHORE_PATH, 0777);
	if (err != 0 && errno != EEXIST) {
		err = -errno;
		resourceDestroy(semaphore_common.lock);
		free(object);
		return err;
	}

	posixsrv_object_create(object, &semaphore_control_ops);
	err = posixsrv_object_link(object, SEMCTL_PATH);
	posixsrv_object_put(object);
	return err;
}
