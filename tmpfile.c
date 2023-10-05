/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - tmpfile
 *
 * Copyright 2018 Phoenix Systems
 * Author: Kamil Amanowicz
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/threads.h>
#include <posix/idtree.h>

#include "posixsrv_private.h"

#ifdef TRACE_TMPFILE
#define TMP_TRACE(str, ...) printf("posixsrv tmpfile: " str "\n", ##__VA_ARGS__)
#else
#define TMP_TRACE(str, ...)
#endif

#define TMPFILE_PATH "/var/tmp/tmpfile_"

static handler_t tmpfile_open_op, tmpfile_close_op, tmpfile_fw_op;
static void tmpfile_release_op(object_t *o);


static operations_t tmpfile_server_ops = {
	.handlers = { NULL },
	.open = tmpfile_open_op,
};


static operations_t tmpfile_ops = {
	.handlers = { NULL },
	.close = tmpfile_close_op,
	.read = tmpfile_fw_op,
	.write = tmpfile_fw_op,
	.getattr = tmpfile_fw_op,
	.release = tmpfile_release_op,
};


typedef struct _tmpfile_t {
	object_t o;
	handle_t lock;

	int fd;
	oid_t oid;
	char *path;
} tmpfile_t;


void tmpfile_set_msg_oid(msg_t *msg, oid_t *oid)
{
	switch(msg->type) {

	case mtGetAttr:
		memcpy(&msg->i.attr.oid, oid, sizeof(oid_t));
		break;
	case mtRead:
	case mtWrite:
		memcpy(&msg->i.io.oid, oid, sizeof(oid_t));
		break;
	default:
		TMP_TRACE("can't set oid for msg type %d", msg->type);
		break;
	}
}


static request_t *tmpfile_fw_op(object_t *o, request_t *r)
{
	TMP_TRACE("forward operation type %d", r->msg.type);
	int err;
	tmpfile_t *tmpfile = (tmpfile_t *)o;

	mutexLock(tmpfile->lock);
	tmpfile_set_msg_oid(&r->msg, &tmpfile->oid);
	err	= msgSend(tmpfile->oid.port, &r->msg);
	mutexUnlock(tmpfile->lock);

	if (err)
		rq_setResponse(r, err);

	return r;
}


static request_t *tmpfile_close_op(object_t *o, request_t *r)
{
	TMP_TRACE("close operation");
	posixsrv_object_destroy(o);
	posixsrv_object_put(o);
	return r;
}


static void tmpfile_release_op(object_t *o)
{
	TMP_TRACE("release operation");
	tmpfile_t *tmpfile = (tmpfile_t *)o;

	close(tmpfile->fd);
	unlink(tmpfile->path);
	resourceDestroy(tmpfile->lock);
	free(tmpfile->path);
	free(tmpfile);
}


static int tmpfile_open(int *id)
{

	tmpfile_t *tmpfile;
	char *path;

	tmpfile = malloc(sizeof(tmpfile_t));

	if (tmpfile == NULL)
		return -ENOMEM;

	if (mutexCreate(&tmpfile->lock) < 0) {
		free(tmpfile);
		return -ENOMEM;
	}

	posixsrv_object_create(&tmpfile->o, &tmpfile_ops);
	*id = posixsrv_object_id(&tmpfile->o);
	asprintf(&path, "%s%d", TMPFILE_PATH, *id);

	tmpfile->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, DEFFILEMODE);
	if (tmpfile->fd < 0) {
		tmpfile_close_op(&tmpfile->o, NULL);
		return -1;
	}

	if (lookup(path, NULL, &tmpfile->oid) < 0) {
		tmpfile_close_op(&tmpfile->o, NULL);
		return -1;
	}

	tmpfile->path = path;
	return 0;
}


static request_t *tmpfile_open_op(object_t *o, request_t *r)
{
	TMP_TRACE("open");
	int id, err;

	err = tmpfile_open(&id);

	if (!err) err = id;
	rq_setResponse(r, err);
	return r;
}


int tmpfile_init()
{
	object_t *o;
	int err;

	mkdir("/var/tmp", 0777);

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	posixsrv_object_create(o, &tmpfile_server_ops);
	err = posixsrv_object_link(o, "/dev/posix/tmpfile");
	posixsrv_object_put(o);
	return err;
}
