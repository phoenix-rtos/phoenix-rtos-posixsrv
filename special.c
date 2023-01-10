/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - /dev/{zero,null}
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
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "posixsrv_private.h"


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


static request_t *zero_read_op(object_t *o, request_t *r)
{
	memset(r->msg.o.data, 0, r->msg.o.size);
	rq_setResponse(r, r->msg.o.size);
	return r;
}


#ifndef NOPRNG
static request_t *random_read_op(object_t *o, request_t *r)
{
	int len = r->msg.o.size;
	uint8_t* buf = r->msg.o.data;

	while (len >= 4) {
		*((int*)buf) = rand();
		len -= 4;
		buf += 4;
	}

	while (len > 0) {
		*buf++ = (uint8_t) rand();
		len -= 1;
	}

	rq_setResponse(r, r->msg.o.size);
	return r;
}
#endif


static request_t *null_getattr_op(object_t *o, request_t *r)
{
	int err;

	if (r->msg.i.attr.type == atPollStatus)
		err = POLLOUT;
	else
		err = -EINVAL;

	rq_setResponse(r, err);
	return r;
}


static request_t *zero_getattr_op(object_t *o, request_t *r)
{
	int err;

	if (r->msg.i.attr.type == atPollStatus)
		err = POLLIN;
	else
		err = -EINVAL;

	rq_setResponse(r, err);
	return r;
}


static operations_t null_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = null_read_op,
	.write = null_write_op,
	.getattr = null_getattr_op,
	.truncate = nothing_op,
	.release = (void *)free,
};


static operations_t zero_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = zero_read_op,
	.write = null_write_op,
	.getattr = zero_getattr_op,
	.release = (void *)free,
};


#ifndef NOPRNG
static operations_t random_ops = {
	.handlers = { NULL },
	.open = nothing_op,
	.close = nothing_op,
	.read = random_read_op,
	.write = null_write_op,
	.getattr = zero_getattr_op,
	.release = (void *)free,
};
#endif


int special_init()
{
	object_t *o;
	int err;

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	object_create(o, &null_ops);
	err = object_link(o, "/dev/null");
	object_put(o);

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	object_create(o, &zero_ops);
	err = object_link(o, "/dev/zero");
	object_put(o);

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

#ifndef NOPRNG
	srand(time(NULL));
	object_create(o, &random_ops);
	err = object_link(o, "/dev/urandom");
	object_put(o);
#endif

	return err;
}
