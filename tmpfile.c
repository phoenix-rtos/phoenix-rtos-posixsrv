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

#define TMPFILE_PATH     "/var/tmp/tmpfile_"
#define TMPFILE_PATH_MAX TMPFILE_PATH "2147483647"

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
	/* TODO: implement missing ops */
	.release = tmpfile_release_op,
};


typedef struct _tmpfile_t {
	object_t o;
	handle_t lock;

	int fd;
	int id;
	oid_t oid;
} tmpfile_t;


static request_t *tmpfile_fw_op(object_t *o, request_t *r)
{
	TMP_TRACE("forward operation type %d", r->msg.type);
	int err;
	tmpfile_t *tmpfile = (tmpfile_t *)o;

	mutexLock(tmpfile->lock);
	r->msg.oid = tmpfile->oid;
	err	= msgSend(tmpfile->oid.port, &r->msg);
	mutexUnlock(tmpfile->lock);

	if (err != 0) {
		rq_setResponse(r, err);
	}

	return r;
}


static request_t *tmpfile_close_op(object_t *o, request_t *r)
{
	TMP_TRACE("close operation");
	posixsrv_object_destroy(o);
	posixsrv_object_put(o);
	return r;
}


static inline int tmpfile_sprintPath(char *pathbuf, int id)
{
	if (id == -1) {
		return -ENOENT;
	}

	if (sprintf(pathbuf, TMPFILE_PATH "%d", id) < 0) {
		return -errno;
	}

	return 0;
}


static void tmpfile_release_op(object_t *o)
{
	TMP_TRACE("release operation");
	tmpfile_t *tmpfile = (tmpfile_t *)o;
	char path[sizeof(TMPFILE_PATH_MAX)];

	if (tmpfile->fd != -1) {
		close(tmpfile->fd);
		if (tmpfile_sprintPath(path, tmpfile->id) >= 0) {
			unlink(path);
		}
	}
	if (tmpfile->lock != -1) {
		resourceDestroy(tmpfile->lock);
	}
	free(tmpfile);
}


static int tmpfile_open(void)
{
	int err;
	tmpfile_t *tmpfile;
	char path[sizeof(TMPFILE_PATH_MAX)];

	tmpfile = malloc(sizeof(tmpfile_t));
	if (tmpfile == NULL) {
		return -ENOMEM;
	}
	tmpfile->fd = -1;
	tmpfile->lock = -1;
	tmpfile->id = -1;

	if (mutexCreate(&tmpfile->lock) < 0) {
		free(tmpfile);
		return -ENOMEM;
	}

	posixsrv_object_create(&tmpfile->o, &tmpfile_ops);
	tmpfile->id = posixsrv_object_id(&tmpfile->o);
	err = tmpfile_sprintPath(path, tmpfile->id);
	if (err < 0) {
		tmpfile_close_op(&tmpfile->o, NULL);
		return err;
	}

	tmpfile->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, DEFFILEMODE);
	if (tmpfile->fd < 0) {
		err = -errno;
		tmpfile_close_op(&tmpfile->o, NULL);
		return err;
	}

	err = lookup(path, NULL, &tmpfile->oid);
	if (err < 0) {
		tmpfile_close_op(&tmpfile->o, NULL);
		return err;
	}

	return tmpfile->id;
}


static request_t *tmpfile_open_op(object_t *o, request_t *r)
{
	TMP_TRACE("open");
	int err;

	err = tmpfile_open();
	rq_setResponse(r, err);
	return r;
}


int tmpfile_init(void)
{
	object_t *o;
	int err;

	if (mkdir("/var", 0777) < 0 && errno != EEXIST) {
		TMP_TRACE("posixsrv tmpfile: failed to create /var directory\n");
		return -errno;
	}

	if (mkdir("/var/tmp", 0777) < 0 && errno != EEXIST) {
		TMP_TRACE("posixsrv tmpfile: failed to create /var/tmp directory\n");
		return -errno;
	}

	if ((o = malloc(sizeof(*o))) == NULL)
		return -ENOMEM;

	posixsrv_object_create(o, &tmpfile_server_ops);
	err = posixsrv_object_link(o, "/dev/posix/tmpfile");
	posixsrv_object_put(o);
	return err;
}
