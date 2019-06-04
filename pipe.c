/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - pipes
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <sys/threads.h>

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include "posixsrv.h"
#include "fifo.h"

#define PIPE_FIFO_SIZE 0x1000

#define pipe_node(n) ((pipe_t *)((char *)n - offsetof(pipe_t, node)))


typedef struct _pipe_t {
	node_t node;
	handle_t lock;

	queue_t retry_read;
	queue_t retry_write;

	fifo_t fifo;
} pipe_t;


static void pipe_lock(pipe_t *pipe)
{
	mutexLock(pipe->lock);
}


static void pipe_unlock(pipe_t *pipe)
{
	mutexUnlock(pipe->lock);
}


static void pipe_destroy(node_t *node)
{
	pipe_t *pipe = pipe_node(node);

	resourceDestroy(pipe->lock);
	free(pipe);
}


static int pipe_open(request_t *request, file_t *file)
{
	/* TODO */
	return EOK;
}


static int pipe_close(file_t *file)
{
	/* TODO */
	return EOK;
}


static int pipe_truncate(file_t *file, int *retval, off_t offset)
{
	return EOK;
}


static int pipe_write(request_t *request, file_t *file, ssize_t *retval, void *data, size_t bytes)
{
	pipe_t *pipe = pipe_node(file->node);
	int err;

	pipe_lock(pipe);
	if (fifo_is_full(&pipe->fifo)) {
		err = request_queue_retry(request, file, &pipe->retry_write);
		pipe_unlock(pipe);
		return err;
	}

	*retval = fifo_write(&pipe->fifo, data, bytes);
	request_continue(&pipe->retry_read);
	pipe_unlock(pipe);
	return EOK;
}


static int pipe_read(request_t *request, file_t *file, ssize_t *retval, void *data, size_t bytes)
{
	pipe_t *pipe = pipe_node(file->node);
	int err;

	pipe_lock(pipe);
	if (fifo_is_empty(&pipe->fifo)) {
		err = request_queue_retry(request, file, &pipe->retry_read);
		pipe_unlock(pipe);
		return err;
	}

	*retval = fifo_read(&pipe->fifo, data, bytes);
	request_continue(&pipe->retry_write);
	pipe_unlock(pipe);
	return EOK;
}


static const file_ops_t pipe_ops = {
	.open = pipe_open,
	.close = pipe_close,
	.read = pipe_read,
	.write = pipe_write,
	.truncate = pipe_truncate,
};


int pipe_create(node_t **node)
{
	pipe_t *pipe = malloc(sizeof(*pipe) + PIPE_FIFO_SIZE);
	int err;

	if (pipe == NULL)
		return ENOMEM;

	if ((err = mutexCreate(&pipe->lock)) < 0) {
		free(pipe);
		return -err;
	}

	fifo_init(&pipe->fifo, PIPE_FIFO_SIZE);

	request_queue_init(&pipe->retry_read);
	request_queue_init(&pipe->retry_write);

	pipe->node.refs = 1;
	pipe->node.ops = &pipe_ops;
	pipe->node.destroy = pipe_destroy;
	*node = &pipe->node;
	return EOK;
}

