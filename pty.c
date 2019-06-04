/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - pseudoterminals
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <sys/threads.h>
#include <sys/stat.h>

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include <libtty.h>

#include "posixsrv.h"

#define PTY_BUFFER_SIZE 0x4000
#define pty_node(n) ((pty_t *)((char *)n - offsetof(pty_t, node)))


struct {
	oid_t devpts;
	node_t ptmx;
} pty_common;


typedef struct _pty_t {
	node_t node;
	handle_t lock;

	unsigned unlocked : 1;
	int id;

	queue_t master_read;
	queue_t slave_read;
	queue_t slave_write;

	libtty_common_t tty;
	libtty_callbacks_t ops;
} pty_t;


static void pty_lock(pty_t *pty)
{
	mutexLock(pty->lock);
}


static void pty_unlock(pty_t *pty)
{
	mutexUnlock(pty->lock);
}


static void pty_destroy(node_t *node)
{
	pty_t *pty = pty_node(node);

	resourceDestroy(pty->lock);
	libtty_destroy(&pty->tty);
	free(pty);
}


static void pty_basename(pty_t *pty, char *buffer, int size)
{
	snprintf(buffer, size, "%d", pty->id);
}


static int pty_link(pty_t *pty)
{
	int err;
	char name[32];

	pty->id = node_add(&pty->node);
	pty_basename(pty, name, sizeof(name));
	err = fs_create_special(pty_common.devpts, name, pty->id, S_IFCHR);
	return err;
}


static void pty_unlink(pty_t *pty)
{
	char name[32];

	pty_basename(pty, name, sizeof(name));
	msg_unlink(pty_common.devpts, name);
}


static void signal_txready(void *arg)
{
	pty_t *pty = arg;

	pty_lock(pty);
	request_continue(&pty->master_read);
	pty_unlock(pty);
}


static int pts_open(request_t *request, file_t *file)
{
	pty_t *pty = pty_node(file->node);

	if (pty->unlocked)
		return EOK;

	return EACCES;
}


static int pts_close(file_t *file)
{
	return EOK;
}


static int pts_write(request_t *request, file_t *file, ssize_t *retval, void *data, size_t bytes)
{
	pty_t *pty = pty_node(file->node);
	*retval = libtty_write(&pty->tty, data, bytes, file->mode);
	return EOK;
}


static int pts_read(request_t *request, file_t *file, ssize_t *retval, void *data, size_t bytes)
{
	pty_t *pty = pty_node(file->node);
	*retval = libtty_read(&pty->tty, data, bytes, file->mode);
	return EOK;
}


static int pts_ioctl(file_t *file, pid_t sender_pid, unsigned int cmd, const void* in_arg, const void** out_arg)
{
	pty_t *pty = pty_node(file->node);
	return -libtty_ioctl(&pty->tty, sender_pid, cmd, in_arg, out_arg);
}


static const file_ops_t pts_ops = {
	.open = pts_open,
	.close = pts_close,
	.read = pts_read,
	.write = pts_write,
	.ioctl = pts_ioctl,
};


static int ptm_write(request_t *request, file_t *file, ssize_t *retval, char *data, size_t bytes)
{
	pty_t *pty = pty_node(file->node);
	int wake_reader;
	ssize_t count = 0;

	pty_lock(pty);
	while (bytes--)
		libtty_putchar(&pty->tty, data[count++], &wake_reader);

	if (wake_reader)
		request_continue(&pty->slave_read);
	pty_unlock(pty);

	*retval = count;
	return EOK;
}


static int ptm_open(request_t *request, file_t *file)
{
	file->ops = &pts_ops;
	return pts_open(request, file);
}


static int ptm_close(file_t *file)
{
	pty_t *pty = pty_node(file->node);
	libtty_close(&pty->tty);
	pty_unlink(pty);
	return EOK;
}


static int ptm_read(request_t *request, file_t *file, ssize_t *retval, char *data, size_t bytes)
{
	pty_t *pty = pty_node(file->node);
	int wake_writer, err = EOK;
	ssize_t count = 0;

	pty_lock(pty);
	while (libtty_txready(&pty->tty) && bytes--)
		data[count++] = libtty_getchar(&pty->tty, &wake_writer);

	if (wake_writer)
		request_continue(&pty->slave_write);

	if (!count)
		err = request_queue_retry(request, file, &pty->master_read);
	pty_unlock(pty);

	*retval = count;
	return err;
}


static int ptm_ioctl(file_t *file, pid_t sender_pid, unsigned int cmd, const void* in_arg, const void** out_arg)
{
	pty_t *pty = pty_node(file->node);
	int err = EOK, lock;

	switch (cmd) {
	case TIOCGPTN: /* get pty number */
		*(int **)out_arg = &pty->id;
		break;

	case TIOCSPTLCK: /* (un)lock slave */
		lock = !!*(int *)in_arg;
		if (lock ^ pty->unlocked)
			err = EINVAL;
		else
			pty->unlocked = !pty->unlocked;
		break;

	default:
		err = EINVAL;
		break;
	}

	return err;
}


static const file_ops_t ptm_ops = {
	.open = ptm_open,
	.close = ptm_close,
	.read = ptm_read,
	.write = ptm_write,
	.ioctl = ptm_ioctl,
};


static int pty_create(node_t **node)
{
	pty_t *pty = malloc(sizeof(*pty));
	int err;

	if (pty == NULL)
		return ENOMEM;

	if ((err = mutexCreate(&pty->lock)) < 0) {
		free(pty);
		return -err;
	}

	pty->ops.arg = pty;

	pty->ops.set_baudrate = NULL;
	pty->ops.set_cflag = NULL;
	pty->ops.signal_txready = signal_txready;

	pty->unlocked = 0;

	if (libtty_init(&pty->tty, &pty->ops, PTY_BUFFER_SIZE)) {
		free(pty);
		return ENOMEM;
	}

	request_queue_init(&pty->master_read);
	request_queue_init(&pty->slave_read);
	request_queue_init(&pty->slave_write);

	pty->node.refs = 1;
	pty->node.ops = &ptm_ops;
	pty->node.destroy = pty_destroy;
	*node = &pty->node;
	return EOK;
}


static int ptmx_open(request_t *request, file_t *file)
{
	int err;

	node_put(file->node);
	file->node = NULL;

	err = pty_create(&file->node);
	file->ops = NULL;

	if (!err) {
		file->ops = &ptm_ops;
		pty_link(pty_node(file->node));
	}

	return err;
}


static int ptmx_close(file_t *file)
{
	return EOK;
}


static const file_ops_t ptmx_ops = {
	.open = ptmx_open,
	.close = ptmx_close,
};


int pty_init(void)
{
	oid_t dev;
	int ptmx_id;

	fs_lookup("/dev/pts", &pty_common.devpts);
	fs_lookup("/dev/pts", &dev);

	pty_common.ptmx.refs = 1;
	pty_common.ptmx.ops = &ptmx_ops;
	ptmx_id = node_add(&pty_common.ptmx);

	fs_create_special(dev, "ptmx", ptmx_id, S_IFCHR);
}
