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
	handle_t cond;
	idtree_t objects;
	rbtree_t timeout;

	struct {
		int id;
		object_t *o;
	} cache;
} posixsrv_common;


static void fail(const char *str)
{
	printf("posixsrv fail: %s\n", str);
}


void object_destroy(object_t *o)
{
	o->destroy = 1;
}


object_t *object_get(int id)
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


void object_ref(object_t *o)
{
	while (mutexLock(posixsrv_common.lock) < 0);
	o->refs++;
	mutexUnlock(posixsrv_common.lock);
}


void object_put(object_t *o)
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


int object_create(object_t *o, const operations_t *ops)
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


int object_link(object_t *o, const char *path)
{
	TRACE("linking %d to %s", o->linkage.id, path);
	oid_t oid;

	oid.port = posixsrv_common.port;
	oid.id = o->linkage.id;

	return create_dev(&oid, path);
}


unsigned srv_port(void)
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


void rq_timeout(request_t *r, int ms)
{
	gettime(&r->wakeup, NULL);
	r->wakeup += 1000 * ms;

	mutexLock(posixsrv_common.lock);
	lib_rbInsert(&posixsrv_common.timeout, &r->linkage);
	mutexUnlock(posixsrv_common.lock);
	condSignal(posixsrv_common.cond);
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
			r->msg.o.attr.err = response;
			break;
		}
		r->msg.o.attr.val = response;
		r->msg.o.attr.err = EOK;
		break;
	default:
		/* TODO: other cases */
		r->msg.o.io.err = response;
		break;
	}
}


void rq_wakeup(request_t *r)
{
	TRACE("respond %x", r->rid);
	msgRespond(r->port, &r->msg, r->rid);
	free(r);
}


void rq_timeoutthr(void *arg)
{
	request_t *r;
	time_t now, timeout;

	mutexLock(posixsrv_common.lock);

	for (;;) {
		if ((r = lib_treeof(request_t, linkage, lib_rbMinimum(posixsrv_common.timeout.root))) != NULL) {
			gettime(&now, NULL);

			if (r->wakeup <= now) {
				lib_rbRemove(&posixsrv_common.timeout, &r->linkage);
				if (r->object->operations->timeout != NULL)
					r->object->operations->timeout(r);
				else {
					rq_setResponse(r, -ETIME);
					rq_wakeup(r);
				}
				continue;
			}

			timeout = r->wakeup - now;
		}
		else {
			timeout = 0;
		}

		condWait(posixsrv_common.cond, posixsrv_common.lock, timeout);
	}
}


int rq_id(request_t *r)
{
	int id;
	id_t full_id;

	switch (r->msg.type) {
	case mtOpen:
	case mtClose:
		id = r->msg.i.openclose.oid.id;
		break;

	case mtRead:
	case mtWrite:
	case mtTruncate:
		id = r->msg.i.io.oid.id;
		break;

	case mtCreate:
		id = r->msg.i.create.dir.id;
		break;

	case mtDestroy:
		id = r->msg.i.destroy.oid.id;
		break;

	case mtSetAttr:
	case mtGetAttr:
		id = r->msg.i.attr.oid.id;
		break;

	case mtLookup:
		id = r->msg.i.lookup.dir.id;
		break;

	case mtLink:
	case mtUnlink:
		id = r->msg.i.ln.oid.id;
		break;

	case mtReaddir:
		id = r->msg.i.readdir.dir.id;
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


void posixsrvthr(void *arg)
{
	object_t *o;
	unsigned port = (unsigned)arg;
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
		if (msgRecv(port, &r->msg, &r->rid) < 0)
			continue;

		o = object_get(rq_id(r));

		/* Can't handle msg - wrong object id or wrong operation */
		if (o == NULL || o->operations->handlers[r->msg.type] == NULL) {
			if (o != NULL)
				object_put(o);
			r->msg.o.io.err = -EINVAL;
			msgRespond(port, &r->msg, r->rid);
			continue;
		}

		r->object = o;
		r = o->operations->handlers[r->msg.type](o, r);

		/* If an operation returns NULL, it is up to a module to
		 * respond to this msg later and free the request */
		if (r != NULL)
			msgRespond(port, &r->msg, r->rid);

		object_put(o);
	}
}


int posixsrv_init(unsigned *srvPort, unsigned *eventPort)
{
	idtree_init(&posixsrv_common.objects);
	lib_rbInit(&posixsrv_common.timeout, rq_cmp, NULL);
	mutexCreate(&posixsrv_common.lock);
	condCreate(&posixsrv_common.cond);

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

	if (srvPort != NULL) {
		*srvPort = posixsrv_common.port;
	}

	return 0;
}
