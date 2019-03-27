/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - pseudoterminals
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
#include <errno.h>
#include <poll.h>
#include <signal.h>

#include <libtty.h>

#include "posix/idtree.h"
#include "posixsrv_private.h"

//#define PTY_TRACE(str, ...) printf("posixsrv pty: " str "\n", ##__VA_ARGS__)
#define PTY_TRACE(str, ...)

#define MASTER_OPEN   (1 << 0)
#define SLAVE_LOCKED  (1 << 1)
#define SLAVE_OPEN    (1 << 2)
#define PTY_CLOSING   (1 << 3)


static handler_t pts_write_op, pts_read_op, pts_open_op, pts_close_op, pts_devctl_op, pts_getattr_op, pts_setattr_op;
static handler_t ptm_write_op, ptm_read_op, ptm_close_op, ptm_devctl_op, ptm_getattr_op, ptm_setattr_op;
static handler_t ptmx_open_op;

static void ptm_destroy(object_t *o);

static void pts_timeout(request_t *r);

static operations_t pts_ops = {
	.handlers = { NULL },
	.open = pts_open_op,
	.close = pts_close_op,
	.read = pts_read_op,
	.write = pts_write_op,
	.getattr = pts_getattr_op,
	.setattr = pts_setattr_op,
	.devctl = pts_devctl_op,
	.release = NULL,
	.timeout = pts_timeout,
};


static operations_t ptmx_ops = {
	.handlers = { NULL },
	.open = ptmx_open_op,
};


static operations_t ptm_ops = {
	.handlers = { NULL },
	.close = ptm_close_op,
	.read = ptm_read_op,
	.write = ptm_write_op,
	.getattr = ptm_getattr_op,
	.setattr = ptm_setattr_op,
	.devctl = ptm_devctl_op,
	.release = ptm_destroy,
};


typedef struct {
	object_t master, slave;
	libtty_common_t tty;
	libtty_callbacks_t ops;
	unsigned state;
	unsigned short evmask;
	pid_t slave_pid;
	int slave_refs;

	request_t *read_master;

	request_t *write_requests;
	request_t *read_requests;

	handle_t mutex, cond;
} pty_t;


static void pty_cancelRequests(pty_t *pty)
{
	request_t *r;

	while ((r = pty->write_requests) != NULL) {
		LIST_REMOVE(&pty->write_requests, r);
		rq_wakeup(r);
	}

	while ((r = pty->read_requests) != NULL) {
		LIST_REMOVE(&pty->read_requests, r);
		rq_wakeup(r);
	}

	while ((r = pty->read_master) != NULL) {
		LIST_REMOVE(&pty->read_master, r);
		rq_wakeup(r);
	}
}


static inline pty_t *pty_master(object_t *master)
{
	return (void *)master - offsetof(pty_t, master);
}


static inline pty_t *pty_slave(object_t *slave)
{
	return (void *)slave - offsetof(pty_t, slave);
}


static void ptm_destroy(object_t *o)
{
	PTY_TRACE("destroying master %d", object_id(o));
	char buf[32];
	msg_t msg;
	int len;
	pty_t *pty = pty_master(o);

	len = snprintf(buf, sizeof(buf), "%d", object_id(&pty->slave));

	memset(&msg, 0, sizeof(msg));

	if (lookup("/dev/pts", NULL, &msg.i.ln.dir) == EOK) {
		msg.type = mtUnlink;

		msg.i.data = buf;
		msg.i.size = len + 1;

		msgSend(msg.i.ln.dir.port, &msg);
	}

	libtty_close(&pty->tty);

	mutexLock(pty->mutex);
	pty->state |= PTY_CLOSING;
	mutexUnlock(pty->mutex);

	libtty_destroy(&pty->tty);

	resourceDestroy(pty->mutex);
	resourceDestroy(pty->cond);
	free(o);
}


static request_t *_ptm_read(pty_t *pty, request_t *r);


static request_t *_pts_write(pty_t *pty, request_t *r)
{
	int err;

	err = libtty_write(&pty->tty, r->msg.i.data, r->msg.i.size, r->msg.i.io.mode | O_NONBLOCK);
	rq_setResponse(r, err);

	if (err == -EWOULDBLOCK && !(r->msg.i.io.mode & O_NONBLOCK)) {
		LIST_ADD(&pty->write_requests, r);
		r = NULL;
	}

	/* master reads will be woken up by libtty callback */
	return r;
}


static request_t *pts_write_op(object_t *o, request_t *r)
{
	PTY_TRACE("pts_write(%d)", object_id(o));
	pty_t *pty = pty_slave(o);

	mutexLock(pty->mutex);
	r = _pts_write(pty, r);
	mutexUnlock(pty->mutex);

	return r;
}


static void pts_timeout(request_t *r)
{
	pty_t *pty = pty_slave(r->object);

	mutexLock(pty->mutex);
	LIST_REMOVE(&pty->read_requests, r);
	mutexUnlock(pty->mutex);

	rq_wakeup(r);
}


static request_t *_pts_read(pty_t *pty, request_t *r)
{
	int err;

	err = libtty_read_nonblock(&pty->tty, r->msg.o.data, r->msg.o.size, r->msg.i.io.mode, &r->pts_read);
	rq_setResponse(r, err);

	if (r->pts_read.timeout_ms >= 0) {
		LIST_ADD(&pty->read_requests, r);

		if (r->pts_read.timeout_ms)
			rq_timeout(r, r->pts_read.timeout_ms);

		r = NULL;
	}

	/* No action on read from slave, master drops data that can not be written */
	return r;
}


static request_t *pts_read_op(object_t *o, request_t *r)
{
	PTY_TRACE("pts_read(%d)", object_id(o));
	pty_t *pty = pty_slave(o);

	libtty_read_state_init(&r->pts_read);
	mutexLock(pty->mutex);
	r = _pts_read(pty, r);
	mutexUnlock(pty->mutex);
	return r;
}


static request_t *pts_open_op(object_t *o, request_t *r)
{
	PTY_TRACE("pts_open(%d)", object_id(o));
	pty_t *pty = pty_slave(o);

	mutexLock(pty->mutex);
	if (pty->state & PTY_CLOSING) {
		rq_setResponse(r, -EPIPE);
	}
	else if (pty->state & SLAVE_LOCKED) {
		rq_setResponse(r, -EACCES);
	}
	else {
		pty->state |= SLAVE_OPEN;
		pty->slave_refs++;
		pty->slave_pid = r->msg.pid; /* FIXME */
		rq_setResponse(r, EOK);
	}
	mutexUnlock(pty->mutex);

	return r;
}


static request_t *pts_close_op(object_t *o, request_t *r)
{
	PTY_TRACE("pts_close(%d)", object_id(o));
	pty_t *pty = pty_slave(o);

	mutexLock(pty->mutex);
	if (pty->state & SLAVE_OPEN) {
		if (!--pty->slave_refs) {
			pty->state &= ~SLAVE_OPEN;
			pty_cancelRequests(pty);
		}
		rq_setResponse(r, EOK);
	} else {
		rq_setResponse(r, -EACCES);
	}
	mutexUnlock(pty->mutex);

	return r;
}


static request_t *pts_devctl_op(object_t *o, request_t *r)
{
	const void *in, *out;
	long unsigned request;
	pty_t *pty = pty_slave(o);
	pid_t pid = ioctl_getSenderPid(&r->msg);
	int err;

	mutexLock(pty->mutex);
	in = ioctl_unpack(&r->msg, &request, NULL);
	err = libtty_ioctl(&pty->tty, pid, request, in, &out);
	ioctl_setResponse(&r->msg, request, err, out);
	mutexUnlock(pty->mutex);

	return r;
}


static request_t *ptm_write_op(object_t *o, request_t *r)
{
	PTY_TRACE("ptm_write(%d, %d)", object_id(o), r->msg.i.size);
	pty_t *pty = pty_master(o);
	size_t i;
	int wake_reader = 0;
	request_t *reader;
	event_t event = {0};

	/* On master write wake pending slave readers up */
	for (i = 0; i < r->msg.i.size; ++i)
		libtty_putchar(&pty->tty, ((unsigned char *)r->msg.i.data)[i], &wake_reader);

	mutexLock(pty->mutex);
	if (wake_reader && ((reader = pty->read_requests) != NULL)) {
		LIST_REMOVE(&pty->read_requests, reader);

		if ((reader = _pts_read(pty, reader)) != NULL)
			rq_wakeup(reader);

		wake_reader = libtty_poll_status(&pty->tty) & POLLIN;
	}
	mutexUnlock(pty->mutex);

	if (wake_reader && (pty->evmask & (1 << evtDataIn))) {
		event.oid.port = srv_port();
		event.oid.id = object_id(&pty->slave);
		event.type = evtDataIn;

		eventsSend(&event, 1);
	}

	rq_setResponse(r, i);
	return r;
}


static request_t *_ptm_read(pty_t *pty, request_t *r)
{
	int i, wake_writer;
	request_t *writer;
	event_t event = {0};

	if (pty->state & PTY_CLOSING) {
		rq_setResponse(r, -EBADF);
		return r;
	}

	if (!libtty_txready(&pty->tty)) {
		if (r->msg.i.io.mode & O_NONBLOCK) {
			rq_setResponse(r, -EWOULDBLOCK);
			return r;
		}

		LIST_ADD(&pty->read_master, r);
		return NULL;
	}
	mutexUnlock(pty->mutex);

	for (i = 0; i < r->msg.o.size && libtty_txready(&pty->tty); ++i)
		((unsigned char *)r->msg.o.data)[i] = libtty_getchar(&pty->tty, &wake_writer);

	mutexLock(pty->mutex);
	rq_setResponse(r, i);

	/* On master read wake pending slave writers up */
	if (wake_writer && (writer = pty->write_requests) != NULL) {
		LIST_REMOVE(&pty->write_requests, writer);

		if ((writer = _pts_write(pty, writer)) != NULL)
			rq_wakeup(writer);

		wake_writer = libtty_poll_status(&pty->tty) & POLLOUT;
	}

	if (wake_writer && (pty->evmask & (1 << evtDataOut))) {
		event.oid.port = srv_port();
		event.oid.id = object_id(&pty->slave);
		event.type = evtDataOut;

		eventsSend(&event, 1);
	}

	return r;
}


static request_t *ptm_read_op(object_t *o, request_t *r)
{
	PTY_TRACE("ptm_read(%d)", object_id(o));
	pty_t *pty = pty_master(o);

	mutexLock(pty->mutex);
	r = _ptm_read(pty, r);
	mutexUnlock(pty->mutex);

	return r;
}


static request_t *ptm_close_op(object_t *o, request_t *r)
{
	PTY_TRACE("ptm_close(%d)", object_id(o));

	pty_t *pty = pty_master(o);

	pty->state &= ~MASTER_OPEN;
	object_destroy(&pty->slave);
	pty_cancelRequests(pty);
	object_put(&pty->slave);

	libtty_signal_pgrp(&pty->tty, SIGHUP);
	object_destroy(o);

	PTY_TRACE("ptm_close(%d): %d slave refs, %d slave object refs, %d master object refs", object_id(o), pty->slave_refs,
		pty->slave.refs, pty->master.refs);

	return r;
}


static request_t *pts_setattr_op(object_t *o, request_t *r)
{
	PTY_TRACE("pts_setattr(%d)", object_id(o));

	pty_t *pty = pty_slave(o);

	if (r->msg.i.attr.type == atEventMask) {
		r->msg.o.attr.val = pty->evmask;
		pty->evmask = r->msg.i.attr.val;
	}
	else {
		r->msg.o.attr.val = -EINVAL;
	}

	return r;
}


static request_t *ptm_setattr_op(object_t *o, request_t *r)
{
	PTY_TRACE("ptm_setattr(%d)", object_id(o));

	pty_t *pty = pty_master(o);

	if (r->msg.i.attr.type == atEventMask) {
		r->msg.o.attr.val = pty->evmask;
		pty->evmask = r->msg.i.attr.val;
	}
	else {
		r->msg.o.attr.val = -EINVAL;
	}

	return r;
}


static request_t *pts_getattr_op(object_t *o, request_t *r)
{
	pty_t *pty = pty_slave(o);

	if (r->msg.i.attr.type != atPollStatus) {
		r->msg.o.attr.val = -EINVAL;
		return r;
	}

	r->msg.o.attr.val = libtty_poll_status(&pty->tty) & r->msg.i.attr.val;
	return r;
}


static request_t *ptm_getattr_op(object_t *o, request_t *r)
{
	pty_t *pty = pty_master(o);
	unsigned ev , rev = 0;

	if (r->msg.i.attr.type != atPollStatus) {
		r->msg.o.attr.val = -EINVAL;
		return r;
	}

	ev = r->msg.i.attr.val;

	if (ev & POLLIN && libtty_txready(&pty->tty))
		rev |= POLLIN;

	if (ev & POLLOUT)
		rev |= POLLOUT;

	r->msg.o.attr.val = rev;
	return r;
}


static request_t *ptm_devctl_op(object_t *o, request_t *r)
{
	PTY_TRACE("ptm_devctl(%d)", object_id(o));
	pty_t *pty = pty_master(o);
	int err = -EINVAL;
	unsigned long request;
	unsigned ptyid;
	const void *in_data, *out_data;

	in_data = ioctl_unpack(&r->msg, &request, NULL);

	PTY_TRACE("ptm_devctl request: %lx", request);

	switch (request) {
	case TIOCGPTN: /* get pty number */
		ptyid = object_id(&pty->slave);
		out_data = &ptyid;
		err = EOK;
		break;

	case TIOCSPTLCK: /* (un)lock slave */
		if (!*((int *)in_data) && pty->state & SLAVE_LOCKED) {
			pty->state &= ~SLAVE_LOCKED;
			err = EOK;
		}
		else if (*((int *)in_data) && !(pty->state & SLAVE_LOCKED)) {
			pty->state |= SLAVE_LOCKED;
			err = EOK;
		}
		break;
	}

	ioctl_setResponse(&r->msg, request, err, out_data);
	return r;
}


void ptm_signalReady(void *arg)
{
	pty_t *pty = arg;
	request_t *r;

	if ((r = pty->read_master) != NULL) {
		LIST_REMOVE(&pty->read_master, r);
		if ((r = _ptm_read(pty, r)) != NULL)
			rq_wakeup(r);
	}
}


#define PTS_NAME_PADDING "XXXXXXXXXX"

static int ptm_create(int *id)
{
	PTY_TRACE("create master/slave pair");

	pty_t *pty;
	oid_t oid;
	char path[] = "/dev/pts/" PTS_NAME_PADDING;

	if ((pty = malloc(sizeof(*pty))) == NULL)
		return -ENOMEM;

	pty->ops.arg = pty;

	pty->ops.set_baudrate = NULL;
	pty->ops.set_cflag = NULL;
	pty->ops.signal_txready = ptm_signalReady;

	pty->evmask = 0;
	pty->read_master = pty->write_requests = pty->read_requests = NULL;

	mutexCreate(&pty->mutex);
	condCreate(&pty->cond);

	if (libtty_init(&pty->tty, &pty->ops, SIZE_PAGE) < 0) {
		free(pty);
		return -ENOMEM;
	}

	pty->state = MASTER_OPEN | SLAVE_LOCKED;
	pty->slave_refs = 0;

	object_create(&pty->master, &ptm_ops);
	object_create(&pty->slave, &pts_ops);

	*id = object_id(&pty->master);
	oid.port = srv_port();
	oid.id = object_id(&pty->slave);
	snprintf(path + sizeof("/dev/pts"), sizeof(PTS_NAME_PADDING), "%d", (int)oid.id);

	object_put(&pty->master);
	return create_dev(&oid, path);
}

#undef PTS_NAME_PADDING


static request_t *ptmx_open_op(object_t *ptmx, request_t *r)
{
	PTY_TRACE("ptmx_open(%d)", object_id(ptmx));
	int id, err;

	err = ptm_create(&id);

	if (!err) err = id;
	rq_setResponse(r, err);
	return r;
}


int pty_init()
{
	object_t *o;
	int err;

	mkdir("/dev/pts", 0);

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	object_create(o, &ptmx_ops);
	err = object_link(o, "/dev/ptmx");
	object_put(o);
	return err;
}