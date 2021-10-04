/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - pipes
 *
 * Copyright 2018 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/minmax.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/msg.h>
#include <sys/file.h>
#include <sys/threads.h>
#include <sys/list.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <posix/idtree.h>
#include <sys/events.h>

#include "posixsrv_private.h"


//#define PIPE_TRACE(str, ...) printf("posixsrv pipes: " str "\n", ##__VA_ARGS__)
#define PIPE_TRACE(str, ...)


static handler_t pipe_create_op, pipe_write_op, pipe_read_op, pipe_open_op, pipe_close_op, pipe_link_op, pipe_unlink_op;
static handler_t pipe_setattr_op, pipe_getattr_op;


static int pipe_lock(handle_t lock, int nonblock)
{
	if (nonblock) return mutexTry(lock);
	while (mutexLock(lock) < 0);
	return 0;
}


static void pipe_destroy(object_t *o);


typedef struct _pipe_t {
	object_t object;
	handle_t lock;

	void *buf;
	unsigned r, w;
	int rrefs, wrefs;
	char full, link;

	unsigned short evmask;

	request_t *queue;
} pipe_t;


static operations_t pipe_server_ops = {
	.handlers = { NULL },
	.create = pipe_create_op,
};


static operations_t pipe_ops = {
	.handlers = { NULL },
	.open = pipe_open_op,
	.close = pipe_close_op,
	.read = pipe_read_op,
	.write = pipe_write_op,
	.link = pipe_link_op,
	.unlink = pipe_unlink_op,
	.getattr = pipe_getattr_op,
	.setattr = pipe_setattr_op,
	.release = pipe_destroy,
};


int _pipe_free(pipe_t *p)
{
	if (p->w == p->r)
		return p->full ? 0 : PIPE_BUFSZ;

	return (p->r - p->w + PIPE_BUFSZ) & (PIPE_BUFSZ - 1);
}


int pipe_free(object_t *o)
{
	return _pipe_free((pipe_t *)o);
}


int pipe_avail(object_t *o)
{
	return PIPE_BUFSZ - pipe_free(o);
}


int pipe_create(int type, int *id, unsigned open)
{
	PIPE_TRACE("create");
	pipe_t *p;

	if ((p = malloc(sizeof(pipe_t))) == NULL)
		return -ENOMEM;

	if (mutexCreate(&p->lock) < 0) {
		free(p);
		return -ENOMEM;
	}

	if ((p->buf = mmap(NULL, PIPE_BUFSZ, PROT_READ | PROT_WRITE, MAP_NONE, OID_NULL, 0)) == MAP_FAILED) {
		free(p);
		return -ENOMEM;
	}

	p->full = 0;

	object_create(&p->object, &pipe_ops);

	p->rrefs = !!(open & O_RDONLY);
	p->wrefs = !!(open & O_WRONLY);
	p->link = 0;
	p->r = p->w = 0;
	p->queue = NULL;

	object_put(&p->object);

	*id = object_id(&p->object);

	return EOK;
}


static request_t *pipe_create_op(object_t *srv, request_t *r)
{
	int id;
	r->msg.o.create.err = pipe_create(r->msg.i.create.type, &id, r->msg.i.create.mode);
	r->msg.o.create.oid.port = srv_port();
	r->msg.o.create.oid.id = id;
	return r;
}


static void _pipe_wakeup(pipe_t *p, request_t *r, int retval)
{
	PIPE_TRACE("wakeup");
	LIST_REMOVE(&p->queue, r);
	rq_setResponse(r, retval);
	rq_wakeup(r);
}


static void pipe_destroy(object_t *o)
{
	PIPE_TRACE("destroy");
	pipe_t *p = (pipe_t *)o;

	while (p->queue != NULL)
		_pipe_wakeup(p, p->queue, -EPIPE);

	if (p->buf != NULL)
		munmap(p->buf, PIPE_BUFSZ);

	resourceDestroy(p->lock);
	free(o);
}


static int _pipe_write(pipe_t *p, void *buf, size_t sz)
{
	int bytes = 0;

	if (!sz || p->buf == NULL)
		return 0;

	if (p->r == p->w && p->full) {
		PIPE_TRACE("write was full");
		return bytes;
	}

	if (p->r > p->w) {
		memcpy(p->buf + p->w, buf, bytes = min(sz, p->r - p->w));
	}
	else {
		memcpy(p->buf + p->w, buf, bytes = min(sz, PIPE_BUFSZ - p->w));

		if (bytes < sz && p->r) {
			buf += bytes;
			sz -= bytes;
			memcpy(p->buf, buf, min(sz, p->r));
			bytes += min(sz, p->r);
		}
	}

	p->w = (p->w + bytes) % PIPE_BUFSZ;

	if (p->w == p->r)
		p->full = 1;

	PIPE_TRACE("write %d bytes to %d", bytes, object_id(&p->object));

	return bytes;
}


static int _pipe_read(pipe_t *p, void *buf, size_t sz)
{
	int bytes = 0;

	if (!sz || p->buf == NULL)
		return 0;

	if (p->r == p->w && !p->full) {
		PIPE_TRACE("read was empty");
		return bytes;
	}

	if (p->w > p->r) {
		memcpy(buf, p->buf + p->r, bytes = min(sz, p->w - p->r));
	}
	else {
		memcpy(buf, p->buf + p->r, bytes = min(sz, PIPE_BUFSZ - p->r));

		if (bytes < sz) {
			buf += bytes;
			sz -= bytes;
			memcpy(buf, p->buf, min(sz, p->w));
			bytes += min(sz, p->w);
		}
	}

	p->r = (p->r + bytes) % PIPE_BUFSZ;

	if (bytes)
		p->full = 0;

	PIPE_TRACE("read %d bytes from %d", bytes, object_id(&p->object));

	return bytes;
}


void pipe_event(pipe_t *p, int type)
{
	event_t event = { 0 };

	event.oid.port = srv_port();
	event.oid.id = object_id(&p->object);
	event.type = type;

	eventsSend(&event, 1);
}


int pipe_write(pipe_t *p, unsigned mode, request_t *r, int *block)
{
	int sz = rq_sz(r), bytes = 0, c, was_empty;
	void *buf = rq_buf(r);

	if (!sz)
		return 0;

	if (pipe_lock(p->lock, mode & O_NONBLOCK) < 0)
		return -EWOULDBLOCK;

	if (p->rrefs) {
		/* write to pending readers */
		while (p->queue != NULL && !p->full && bytes < sz) {
			memcpy(rq_buf(p->queue), buf + bytes, c = min(sz - bytes, rq_sz(p->queue)));
			PIPE_TRACE("writing %d to pending reader", c);
			_pipe_wakeup(p, p->queue, c);
			bytes += c;
		}

		was_empty = !p->full && (p->r == p->w);

		/* write to buffer */
		if (!(bytes += _pipe_write(p, buf + bytes, sz - bytes))) {
			if (mode & O_NONBLOCK) {
				PIPE_TRACE("write would block");
				bytes = -EWOULDBLOCK;
			}
			else {
				PIPE_TRACE("write blocked");
				*block = 1;
				LIST_ADD(&p->queue, r);
			}
		}
		else if (was_empty) {
			pipe_event(p, evtDataIn);
		}
	}
	else {
		PIPE_TRACE("write broken pipe");
		bytes = -EPIPE;
	}
	mutexUnlock(p->lock);

	return bytes;
}


static request_t *pipe_write_op(object_t *o, request_t *r)
{
	int block = 0;

	r->msg.o.io.err = pipe_write((pipe_t *)o, r->msg.i.io.mode, r, &block);

	if (block)
		return NULL;

	return r;
}


int pipe_read(pipe_t *p, unsigned mode, request_t *r, int *block)
{
	int sz = rq_sz(r), bytes = 0, c, was_full;
	void *buf = rq_buf(r);

	if (!sz)
		return 0;

	if (pipe_lock(p->lock, mode & O_NONBLOCK) < 0)
		return -EWOULDBLOCK;

	/* read from buffer */
	was_full = p->full;
	bytes += _pipe_read(p, buf, sz);

	if (was_full) {
		/* read from pending writers */
		while (p->queue != NULL && bytes < sz) {
			PIPE_TRACE("reading %d from pending writer\n", c);
			memcpy(buf + bytes, rq_buf(p->queue), c = min(sz - bytes, rq_sz(p->queue)));
			_pipe_wakeup(p, p->queue, c);
			bytes += c;
		}

		/* discharge remaining pending writers */
		while (p->queue != NULL && (c = _pipe_write(p, rq_buf(p->queue), rq_sz(p->queue))))
			_pipe_wakeup(p, p->queue, c);

		if (!p->full)
			pipe_event(p, evtDataOut);
	}

	if (!bytes && !p->wrefs) {
		PIPE_TRACE("EOF while reading");
		bytes = -EPIPE;
	}
	else if (!bytes && mode & O_NONBLOCK) {
		PIPE_TRACE("read would block");
		bytes = -EWOULDBLOCK;
	}
	else if (!bytes) {
		PIPE_TRACE("read blocked");
		*block = 1;
		LIST_ADD(&p->queue, r);
	}

	mutexUnlock(p->lock);
	return bytes;
}


static request_t *pipe_read_op(object_t *o, request_t *r)
{
	int block = 0;

	r->msg.o.io.err = pipe_read((pipe_t *)o, r->msg.i.io.mode, r, &block);

	if (block)
		return NULL;

	if (r->msg.o.io.err == -EPIPE)
		r->msg.o.io.err = 0;

	return r;
}


int pipe_open(pipe_t *p, unsigned flags, request_t *r, int *block)
{
	PIPE_TRACE("open %d/%x %s", object_id(&p->object), flags, flags & O_WRONLY ? "W" : "R");

	if (pipe_lock(p->lock, flags & O_NONBLOCK) < 0)
		return -EWOULDBLOCK;

	if (flags & O_WRONLY) {
		if (!p->rrefs) {
			if (p->queue != NULL) {
				/* wakeup pending read open request */
				_pipe_wakeup(p, p->queue, 0);
				p->rrefs++;
			}
			else if (flags & O_NONBLOCK) {
				mutexUnlock(p->lock);
				return -ENXIO;
			}
			else {
				PIPE_TRACE("open for writing blocked");
				LIST_ADD(&p->queue, r);
				mutexUnlock(p->lock);
				*block = 1;
				return 0;
			}
		}

		p->wrefs++;
	}
	else {
		if (!p->wrefs) {
			if (p->queue != NULL) {
				/* wakeup pending write open request */
				_pipe_wakeup(p, p->queue, 0);
				p->wrefs++;
			} else if (flags & O_NONBLOCK) {
				/* successful non-blocking open, pass */
			}
			else {
				PIPE_TRACE("open for reading blocked");
				LIST_ADD(&p->queue, r);
				mutexUnlock(p->lock);
				*block = 1;
				return 0;
			}
		}

		p->rrefs++;
	}

	mutexUnlock(p->lock);
	return 0;
}


static request_t *pipe_open_op(object_t *o, request_t *r)
{
	int block = 0;

	r->msg.o.io.err = pipe_open((pipe_t *)o, r->msg.i.openclose.flags/* | O_NONBLOCK*/, r, &block);

	if (block)
		return NULL;

	return r;
}


int pipe_close(pipe_t *p, unsigned flags, request_t *r)
{
	PIPE_TRACE("close %d/%x %s", object_id(&p->object), flags, flags & O_WRONLY ? "W" : "R");

	while (mutexLock(p->lock) < 0);

	if (flags & O_WRONLY) {
		if (!p->wrefs) {
			mutexUnlock(p->lock);
			return -EINVAL;
		}

		p->wrefs--;

		if (!p->wrefs) {
			while (p->queue != NULL)
				_pipe_wakeup(p, p->queue, 0);
		}
	} else if (flags & O_RDONLY) {
		if (!p->rrefs) {
			mutexUnlock(p->lock);
			return -EINVAL;
		}

		p->rrefs--;

		if (!p->rrefs) {
			while (p->queue != NULL)
				_pipe_wakeup(p, p->queue, -EPIPE);
		}
	}

	if (!p->wrefs && !p->rrefs && !p->link) {
		object_destroy(&p->object);
		mutexUnlock(p->lock);
		return EOK;
	}

	mutexUnlock(p->lock);
	return EOK;
}


static request_t *pipe_close_op(object_t *o, request_t *r)
{
	r->msg.o.io.err = pipe_close((pipe_t *)o, r->msg.i.openclose.flags, r);

	return r;
}


int pipe_link(pipe_t *p, const char *path)
{
	PIPE_TRACE("link %d", object_id(&p->object));

	while (mutexLock(p->lock) < 0);
	p->link++;
	mutexUnlock(p->lock);
	return EOK;
}


static request_t *pipe_link_op(object_t *o, request_t *r)
{
	r->msg.o.io.err = pipe_link((pipe_t *)o, r->msg.i.data);
	return r;
}


int pipe_unlink(pipe_t *p, const char *path)
{
	PIPE_TRACE("unlink %d", object_id(&p->object));

	while (mutexLock(p->lock) < 0);

	if (!p->link) {
		mutexUnlock(p->lock);
		return -EINVAL;
	}

	p->link--;

	if (!(p->wrefs && p->rrefs) && !p->link) {
		object_destroy(&p->object);
		mutexUnlock(p->lock);
		return EOK;
	}

	mutexUnlock(p->lock);
	return EOK;
}


static request_t *pipe_unlink_op(object_t *o, request_t *r)
{
	r->msg.o.io.err = pipe_unlink((pipe_t *)o, r->msg.i.data);
	return r;
}


static request_t *pipe_setattr_op(object_t *o, request_t *r)
{
	PIPE_TRACE("setattr %d", object_id(o));
	pipe_t *p = (pipe_t *)o;

	if (r->msg.i.attr.type == atEventMask) {
		r->msg.o.attr.val = p->evmask;
		r->msg.o.attr.err = EOK;
		p->evmask = r->msg.i.attr.val;
	}
	else {
		r->msg.o.attr.err = -EINVAL;
	}

	return r;
}


static request_t *pipe_getattr_op(object_t *o, request_t *r)
{
	PIPE_TRACE("getattr %d", object_id(o));
	int err = 0;
	pipe_t *p = (pipe_t *)o;
	int free;

	if (r->msg.i.attr.type == atPollStatus) {
		mutexLock(p->lock);
		free = _pipe_free(p);
		if (free)
			err |= POLLOUT;
		if (free != PIPE_BUFSZ)
			err |= POLLIN;
		err &= r->msg.i.attr.val;
		err |= !p->wrefs || !p->rrefs ? POLLHUP : 0;
		mutexUnlock(p->lock);
	}
	else {
		err = -EINVAL;
	}

	rq_setResponse(r, err);
	return r;
}


int pipe_init()
{
	object_t *o;
	int err;

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	object_create(o, &pipe_server_ops);
	err = object_link(o, "/dev/posix/pipes");
	object_put(o);
	return err;
}
