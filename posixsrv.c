/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - implementation
 *
 * Copyright 2018, 2023 Phoenix Systems
 * Author: Jan Sikorski, Gerard Swiderski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/msg.h>
#include <sys/file.h>
#include <sys/threads.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "posix/idtree.h"

#include "posixsrv_private.h"

#if 0
#define TRACE(str, ...) printf("posixsrv: " str "\n", ##__VA_ARGS__)
#else
#define TRACE(str, ...)
#endif


struct {
	unsigned port;

	handle_t lock;
	idtree_t objects;

	/*
	 * Deferred requests waiting for their deadline.
	 *
	 * LOCK ORDER:
	 *   1. subsystem lock (sem->lock, queue->lock, pty->mutex)
	 *   2. posixsrv_common.timeout.lock
	 *   3. posixsrv_common.lock
	 *
	 * Subsystems hold their own lock across rq_timeout() and rq_timeoutCancel(),
	 * so posixsrv_threadRqTimeout() must not hold timeout.lock* while it dispatches
	 * timeout handler.
	 *
	 * posixsrv_common.lock is innermost, posixsrv_object_put() drops it before
	 * calling a release handler, so nothing reaches timeout.lock while holding it.
	 *
	 * INVARIANT: a request is armed only while it is linked on its subsystem's list,
	 * and every path that can release the object first drains that list, cancelling
	 * each request. posixsrv_threadRqTimeout() pins r->object before dispatching, but
	 * it has to read r->object first - so an object released while one of its requests
	 * is still armed would already be gone by then. A new rq_timeout() call site must
	 * arm under the same lock that guards the list it parks the request on, and the
	 * matching rq_timeoutCancel() must be made under that lock too.
	 */
	struct {
		handle_t lock;
		handle_t cond;
		rbtree_t tree;
	} timeout;

	struct {
		int id;
		object_t *o;
	} cache;
} posixsrv_common;


static void fail(const char *str)
{
	printf("posixsrv fail: %s\n", str);
}


void posixsrv_object_destroy(object_t *o)
{
	o->destroy = 1;
}


object_t *posixsrv_object_get(int id)
{
	object_t *o;

	while (mutexLock(posixsrv_common.lock) < 0);

	if (posixsrv_common.cache.id == id)
		o = posixsrv_common.cache.o;
	else
		o = lib_treeof(object_t, linkage, (void *)idtree_find(&posixsrv_common.objects, id));

	if (o != NULL) {
		if (o->destroy) {
			o = NULL;
		}
		else {
			posixsrv_common.cache.id = id;
			posixsrv_common.cache.o = o;
			o->refs++;
		}
	}

	mutexUnlock(posixsrv_common.lock);

	return o;
}


void posixsrv_object_ref(object_t *o)
{
	while (mutexLock(posixsrv_common.lock) < 0);
	o->refs++;
	mutexUnlock(posixsrv_common.lock);
}


void posixsrv_object_put(object_t *o)
{
	while (mutexLock(posixsrv_common.lock) < 0);

	if (!--o->refs && o->destroy) {
		TRACE("removing %d", o->linkage.id);

		if (posixsrv_common.cache.id == o->linkage.id)
			posixsrv_common.cache.o = NULL;

		idtree_remove(&posixsrv_common.objects, &o->linkage);
		mutexUnlock(posixsrv_common.lock);

		if (o->operations->release != NULL)
			o->operations->release(o);

		return;
	}

	mutexUnlock(posixsrv_common.lock);
	return;
}


int posixsrv_object_create(object_t *o, const operations_t *ops)
{
	o->destroy = 0;
	o->operations = ops;
	o->refs = 1;

	while (mutexLock(posixsrv_common.lock) < 0);
	idtree_alloc(&posixsrv_common.objects, &o->linkage);
	posixsrv_common.cache.id = o->linkage.id;
	posixsrv_common.cache.o = o;
	mutexUnlock(posixsrv_common.lock);

	TRACE("created %d", o->linkage.id);

	return EOK;
}


int posixsrv_object_link(object_t *o, const char *path)
{
	TRACE("linking %d to %s", o->linkage.id, path);
	oid_t oid;

	oid.port = posixsrv_common.port;
	oid.id = o->linkage.id;

	return create_dev(&oid, path);
}


unsigned posixsrv_port(void)
{
	return posixsrv_common.port;
}


static int rq_cmp(rbnode_t *n1, rbnode_t *n2)
{
	request_t *r1, *r2;
	r1 = lib_treeof(request_t, linkage, n1);
	r2 = lib_treeof(request_t, linkage, n2);

	if (r2->wakeup > r1->wakeup)
		return 1;
	else if (r2->wakeup < r1->wakeup)
		return -1;
	return 0;
}


void rq_timeout(request_t *r, time_t usecs)
{
	gettime(&r->wakeup, NULL);
	r->wakeup += usecs;

	mutexLock(posixsrv_common.timeout.lock);
	lib_rbInsert(&posixsrv_common.timeout.tree, &r->linkage);
	r->timeoutState = rq_timeoutArmed;
	mutexUnlock(posixsrv_common.timeout.lock);
	condSignal(posixsrv_common.timeout.cond);
}


void rq_timeoutAt(request_t *r, time_t deadline)
{
	r->wakeup = deadline;

	mutexLock(posixsrv_common.timeout.lock);
	lib_rbInsert(&posixsrv_common.timeout.tree, &r->linkage);
	r->timeoutState = rq_timeoutArmed;
	mutexUnlock(posixsrv_common.timeout.lock);
	condSignal(posixsrv_common.timeout.cond);
}


int rq_timeoutCancel(request_t *r)
{
	int owned;

	mutexLock(posixsrv_common.timeout.lock);

	switch (r->timeoutState) {
		case rq_timeoutArmed:
			TRACE("cancel %x", r->rid);
			lib_rbRemove(&posixsrv_common.timeout.tree, &r->linkage);
			r->timeoutState = rq_timeoutIdle;
			owned = 1;
			break;

		case rq_timeoutFired:
			/*
			 * posixsrv_threadRqTimeout() got it first and is completing the
			 * request - it is no longer ours to touch.
			 */
			TRACE("lost %x", r->rid);
			owned = 0;
			break;

		default:
			/* Never armed: nothing to cancel, the caller owns the request. */
			owned = 1;
			break;
	}

	mutexUnlock(posixsrv_common.timeout.lock);

	return owned;
}


void rq_setResponse(request_t *r, int response)
{
	switch (r->msg.type) {
	case mtDevCtl:
		ioctl_setResponse(&r->msg, 0, response, NULL);
		break;
	case mtGetAttr:
	case mtSetAttr:
		if (response < 0) {
			r->msg.o.err = response;
			break;
		}
		r->msg.o.attr.val = response;
		r->msg.o.err = EOK;
		break;
	default:
		/* TODO: other cases */
		r->msg.o.err = response;
		break;
	}
}


void rq_wakeup(request_t *r)
{
	TRACE("wakeup %x", r->rid);
	msgRespond(r->port, &r->msg, r->rid);
	free(r);
}


int rq_id(request_t *r)
{
	int id;
	id_t full_id;

	switch (r->msg.type) {
	case mtOpen:
	case mtClose:
	case mtRead:
	case mtWrite:
	case mtTruncate:
	case mtCreate:
	case mtDestroy:
	case mtSetAttr:
	case mtGetAttr:
	case mtGetAttrAll:
	case mtReaddir:
	case mtLookup:
		id = r->msg.oid.id;
		break;

	case mtLink:
	case mtUnlink:
		id = r->msg.i.ln.oid.id;
		break;

	case mtDevCtl:
		ioctl_unpack(&r->msg, NULL, &full_id);
		id = (int)full_id;
		break;

	default:
		id = -1;
		break;
	}

	return id;
}


void posixsrv_threadMain(void *arg)
{
	object_t *o;
	unsigned port = (uintptr_t)arg;
	request_t *r = NULL;

	for (;;) {
		if (r == NULL) {
			r = malloc(sizeof(*r));
			if (r == NULL) {
				printf("posixsrv: Out of memory\n");
				endthread();
			}
			r->port = port;
		}

		if (msgRecv(port, &r->msg, &r->rid) < 0) {
			continue;
		}

		/* no timeout is armed on this one yet */
		r->timeoutState = rq_timeoutIdle;

		o = posixsrv_object_get(rq_id(r));

		/* Can't handle msg - wrong object id or wrong operation */
		if (o == NULL || o->operations->handlers[r->msg.type] == NULL) {
			if (o != NULL) {
				posixsrv_object_put(o);
			}
			r->msg.o.err = -EINVAL;
			msgRespond(port, &r->msg, r->rid);
			continue;
		}

		r->object = o;
		r = o->operations->handlers[r->msg.type](o, r);

		/* If an operation returns NULL, it is up to a module to
		 * respond to this msg later and free the request */
		if (r != NULL) {
			msgRespond(port, &r->msg, r->rid);
		}

		posixsrv_object_put(o);
	}
}


void posixsrv_threadRqTimeout(void *arg)
{
	request_t *r;
	object_t *o;
	time_t now, timeout;

	for (;;) {
		mutexLock(posixsrv_common.timeout.lock);

		r = lib_treeof(request_t, linkage, lib_rbMinimum(posixsrv_common.timeout.tree.root));
		if (r != NULL) {
			gettime(&now, NULL);

			if (r->wakeup <= now) {
				lib_rbRemove(&posixsrv_common.timeout.tree, &r->linkage);
				r->timeoutState = rq_timeoutFired;
				TRACE("dequeue %x", r->rid);

				/*
				 * A deferred request holds no reference of its own, so pin the
				 * object before anything can drop the last one. This must happen
				 * under timeout.lock: a waker that loses rq_timeoutCancel() is
				 * blocked on it right now, and may release the object as soon as
				 * it runs. The handler frees the request, so keep our own pointer.
				 */
				o = r->object;
				posixsrv_object_ref(o);

				/* handlers take subsystem locks - see the LOCK ORDER note */
				mutexUnlock(posixsrv_common.timeout.lock);

				if (o->operations->timeout != NULL) {
					o->operations->timeout(r);
				}
				else {
					rq_setResponse(r, -ETIME);
					rq_wakeup(r);
				}

				/* drop our reference to the object */
				posixsrv_object_put(o);

				continue;
			}

			timeout = r->wakeup - now;
		}
		else {
			timeout = 0;
		}

		condWait(posixsrv_common.timeout.cond, posixsrv_common.timeout.lock, timeout);
		mutexUnlock(posixsrv_common.timeout.lock);
	}
}


int posixsrv_init(unsigned *srvPort, unsigned *eventPort)
{
	idtree_init(&posixsrv_common.objects);
	mutexCreate(&posixsrv_common.lock);

	lib_rbInit(&posixsrv_common.timeout.tree, rq_cmp, NULL);
	mutexCreate(&posixsrv_common.timeout.lock);
	condCreate(&posixsrv_common.timeout.cond);

	if (portCreate(&posixsrv_common.port) < 0) {
		fail("port create");
		return -1;
	}

	mkdir("/dev", 0777);
	mkdir("/dev/posix", 0777);

	if (special_init() < 0) {
		fail("special init");
		return -1;
	}

	if (event_init(eventPort) < 0) {
		fail("event init");
		return -1;
	}

	if (pipe_init() < 0) {
		fail("pipe init");
		return -1;
	}

	if (pty_init() < 0) {
		fail("pty init");
		return -1;
	}

	if (tmpfile_init() < 0) {
		fail("tmpfile init");
		return -1;
	}

	if (semaphore_init() < 0) {
		fail("semaphore init");
		return -1;
	}

	if (srvPort != NULL) {
		*srvPort = posixsrv_common.port;
	}

	return 0;
}
