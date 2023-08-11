/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - /dev/{zero,null}
 *
 * Copyright 2018, 2023 Phoenix Systems
 * Author: Jan Sikorski, Aleksander Kaminski
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
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "posixsrv_private.h"


static request_t *special_link(object_t *o, request_t *r)
{
	object_ref(o);
	rq_setResponse(r, 0);
	return r;
}


static request_t *special_unlink(object_t *o, request_t *r)
{
	object_put(o);
	rq_setResponse(r, 0);
	return r;
}


static request_t *nothing_op(object_t *o, request_t *r)
{
	return r;
}


static request_t *null_read_op(object_t *o, request_t *r)
{
	rq_setResponse(r, 0);
	return r;
}


static request_t *null_write_op(object_t *o, request_t *r)
{
	rq_setResponse(r, r->msg.i.size);
	return r;
}


static request_t *full_write_op(object_t *o, request_t *r)
{
	rq_setResponse(r, -ENOSPC);
	return r;
}


static request_t *zero_read_op(object_t *o, request_t *r)
{
	memset(r->msg.o.data, 0, r->msg.o.size);
	rq_setResponse(r, r->msg.o.size);
	return r;
}


static request_t *random_read_op(object_t *o, request_t *r)
{
	size_t len = r->msg.o.size;

	while (len > 0) {
		int randbuff[16];
		size_t chunk = (len > sizeof(randbuff)) ? sizeof(randbuff) : len;
		size_t limit = (chunk + sizeof(*randbuff) - 1) / sizeof(*randbuff);
		for (size_t i = 0; i < limit; ++i) {
			randbuff[i] = rand();
		}
		memcpy(r->msg.o.data, randbuff, chunk);
		len -= chunk;
	}

	rq_setResponse(r, r->msg.o.size);
	return r;
}


static request_t *null_getattr_op(object_t *o, request_t *r)
{
	int err = (r->msg.i.attr.type == atPollStatus) ? POLLOUT : -EINVAL;
	rq_setResponse(r, err);
	return r;
}


static request_t *zero_getattr_op(object_t *o, request_t *r)
{
	int err = (r->msg.i.attr.type == atPollStatus) ? POLLOUT : -EINVAL;
	rq_setResponse(r, err);
	return r;
}


static void special_release(object_t *o)
{
	free(o);
}


static const operations_t null_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = null_read_op,
	.write = null_write_op,
	.getattr = null_getattr_op,
	.truncate = nothing_op,
	.link = special_link,
	.unlink = special_unlink,
	.release = special_release
};


static const operations_t zero_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = zero_read_op,
	.write = null_write_op,
	.getattr = zero_getattr_op,
	.link = special_link,
	.unlink = special_unlink,
	.release = special_release
};


static const operations_t full_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = zero_read_op,
	.write = full_write_op,
	.getattr = zero_getattr_op,
	.link = special_link,
	.unlink = special_unlink,
	.release = special_release,
};


static const operations_t random_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = random_read_op,
	.write = null_write_op,
	.getattr = zero_getattr_op,
	.link = special_link,
	.unlink = special_unlink,
	.release = special_release
};


static int special_createFile(const char *path, const operations_t *ops)
{
	object_t *o;
	int err;

	o = malloc(sizeof(*o));
	if (o == NULL) {
		return -ENOMEM;
	}

	err = object_create(o, ops);
	if (err < 0) {
		free(o);
		return err;
	}

	err = object_link(o, path);
	if (err < 0) {
		object_put(o);
		return err;
	}

	object_put(o);

	return 0;
}


int special_init()
{
	int err;

	err = special_createFile("/dev/null", &null_ops);
	if (err < 0) {
		return err;
	}

	err = special_createFile("/dev/zero", &zero_ops);
	if (err < 0) {
		return err;
	}

	srand(time(NULL));
	err = special_createFile("/dev/urandom", &random_ops);
	if (err < 0) {
		return err;
	}

	err = special_createFile("/dev/full", &full_ops);
	if (err < 0) {
		return err;
	}

	return 0;
}
