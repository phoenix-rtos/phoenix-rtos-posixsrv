/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * Pseudoterminal (PTY) server
 *
 * Copyright 2019, 2020 Phoenix Systems
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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

#include <libtty.h>

#define PTY_BUFFER_SIZE 0x1000
#define LOG_ERROR(fmt, ...) do { char __msg[256]; sprintf(__msg, "%s:%d  %s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); debug(__msg); } while (0)
#define LOG_DEBUG(fmt, ...) // do { char __msg[256]; sprintf(__msg, "%s:%d  %s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); debug(__msg); } while (0)

extern int deviceCreate(int dirfd, const char *name, int portfd, id_t id, mode_t mode);

typedef struct _pty_t {
	struct _pty_t *freenext;
	handle_t lock;

	unsigned used : 1;
	unsigned unlocked : 1;
	unsigned master_open : 1;
	unsigned slave_open;

	libtty_common_t tty;
	libtty_callbacks_t ops;
} pty_t;


struct {
	int devpts;
	int port;
	handle_t lock;

	pty_t *freept;
	pty_t pts[64];
} pty_common;


static void common_lock()
{
	mutexLock(pty_common.lock);
}


static void common_unlock()
{
	mutexUnlock(pty_common.lock);
}


static int pty_index(pty_t *pty)
{
	return (pty - pty_common.pts);
}


static int pts_number(pty_t *pty)
{
	return 2 * pty_index(pty);
}


static int ptm_number(pty_t *pty)
{
	return 2 * pty_index(pty) + 1;
}


static pty_t *pty_get(int number)
{
	pty_t *pt;
	int index = number / 2;
	if (index > sizeof(pty_common.pts) / sizeof(pty_common.pts[0]))
		return NULL;
	pt = pty_common.pts + index;
	if (!pt->used)
		return NULL;
	return pt;
}


static void pty_lock(pty_t *pty)
{
	mutexLock(pty->lock);
}


static void pty_unlock(pty_t *pty)
{
	mutexUnlock(pty->lock);
}


static void pty_destroy(pty_t *pty)
{
	LOG_DEBUG("destroying pty id=%u", pty_index(pty));
	pty->used = 0;
	libtty_destroy(&pty->tty);
	resourceDestroy(pty->lock);

	common_lock();
	pty->freenext = pty_common.freept;
	pty_common.freept = pty;
	common_unlock();
}


static void pty_basename(pty_t *pty, char *buffer, int size)
{
	snprintf(buffer, size, "%d", pty_index(pty));
}


static int pty_link(pty_t *pty)
{
	int err;
	char name[32];

	pty_basename(pty, name, sizeof(name));
	err = deviceCreate(pty_common.devpts, name, pty_common.port, pts_number(pty), S_IFCHR);
	return err;
}


static void pty_unlink(pty_t *pty)
{
	char name[32];

	pty_basename(pty, name, sizeof(name));
	unlinkat(pty_common.devpts, name, 0);
}


static void signal_txready(void *arg)
{
	pty_t *pty = arg;
//	LOG_DEBUG("");
	portEvent(pty_common.port, ptm_number(pty), POLLIN);
}


static ssize_t ptm_write(pty_t *pty, char *data, size_t bytes)
{
	int wake_reader;
	ssize_t count = 0;

	while (bytes--)
		libtty_putchar(&pty->tty, data[count++], &wake_reader);

	if (wake_reader) {
		LOG_DEBUG("waking reader");
		portEvent(pty_common.port, pts_number(pty), POLLIN);
	}

	return count;
}


static ssize_t ptm_read(pty_t *pty, char *data, size_t bytes)
{
	int wake_writer;
	ssize_t count = 0;

	while (libtty_txready(&pty->tty) && bytes--)
		data[count++] = libtty_getchar(&pty->tty, &wake_writer);

	if (wake_writer) {
		LOG_DEBUG("waking writer");
		portEvent(pty_common.port, pts_number(pty), POLLOUT);
	}

	return count;
}


static int ptm_ioctl(pty_t *pty, pid_t sender_pid, unsigned int cmd, void *arg)
{
	int err = EOK, lock;

	switch (cmd) {
	case TIOCGPTN: /* get pty number */
		*(int *)arg = pty_index(pty);
		break;

	case TIOCSPTLCK: /* (un)lock slave */
		lock = !!*(int *)arg;
		if (lock ^ pty->unlocked)
			err = -EINVAL;
		else
			pty->unlocked = !pty->unlocked;
		break;

	default:
		err = -EINVAL;
		break;
	}

	return err;
}


static int pty_create(id_t *masterid)
{
	pty_t *pty;
	int error;

	if ((pty = pty_common.freept) == NULL)
		return -ENOMEM;

	if (pty->used) {
		LOG_ERROR("free pty corruption");
		exit(EXIT_FAILURE);
	}

	if ((error = mutexCreate(&pty->lock)) < 0) {
		return error;
	}

	pty->ops.arg = pty;
	pty->ops.set_baudrate = NULL;
	pty->ops.set_cflag = NULL;
	pty->ops.signal_txready = signal_txready;

	if (libtty_init(&pty->tty, &pty->ops, PTY_BUFFER_SIZE)) {
		resourceDestroy(pty->lock);
		return -ENOMEM;
	}

	pty_common.freept = pty->freenext;
	pty->freenext = NULL;

	pty->unlocked = 0;
	pty->used = 1;
	pty->slave_open = 0;
	pty->master_open = 1;
	*masterid = ptm_number(pty);

	LOG_DEBUG("created pty id=%llu, %p", *masterid, pty);

	pty_link(pty);
	return EOK;
}


static void msg_loop(void *arg)
{
	msg_t msg;
	unsigned int rid;
	pty_t *pty;
	int error = -EINVAL;

	for (;;) {
		if (msgRecv(pty_common.port, &msg, &rid) < 0)
			continue;

		if (msg.object == -1) {
			if (msg.type == mtOpen) {
				LOG_DEBUG("ptmx open");
				common_lock();
				error = pty_create(&msg.o.open);
				common_unlock();
			}
			else {
				LOG_DEBUG("ptmx bad msg (%d)", msg.type);
				error = -EOPNOTSUPP;
			}
		}
		else if ((pty = pty_get(msg.object)) == NULL) {
			LOG_ERROR("pt with id %llu not found", msg.object);
			error = -ENXIO;
		}
		else {
			pty_lock(pty);
			if (msg.object & 1) {
				/* master end */
				switch (msg.type) {
				case mtOpen: {
					LOG_DEBUG("ptm open");
					msg.o.open = msg.object;
					error = EOK;
					break;
				}
				case mtClose: {
					LOG_DEBUG("ptm close");
					libtty_close(&pty->tty);
					pty_unlink(pty);

					pty->master_open = 0;
					portEvent(pty_common.port, pts_number(pty), POLLHUP);

					if (!pty->slave_open) {
						pty_destroy(pty);
					}

					error = EOK;
					break;
				}
				case mtWrite: {
					LOG_DEBUG("ptm write");
					if (!pty->slave_open) {
						/* return EPIPE? */
						msg.o.io = 0;
						error = -EPIPE;
					}
					else if ((error = ptm_write(pty, msg.i.data, msg.i.size)) >= 0) {
						msg.o.io = error;
						error = EOK;
						if (!msg.o.io)
							error = -EAGAIN;
					}
					break;
				}
				case mtRead: {
					LOG_DEBUG("ptm read");
					if (!pty->slave_open) {
						LOG_DEBUG("ptm read, slave closed");
						/* return EPIPE? */
						msg.o.io = 0;
						error = 0;
					}
					else if ((error = ptm_read(pty, msg.o.data, msg.o.size)) >= 0) {
						msg.o.io = error;
						error = EOK;
						if (!msg.o.io)
							error = -EAGAIN;
					}
					break;
				}
				case mtDevCtl: {
					LOG_DEBUG("ptm ioctl");
					void *buffer;
					size_t size;

					switch (msg.i.devctl & IOC_DIRMASK) {
					case IOC_IN:
						buffer = msg.i.data;
						size = msg.i.size;
						break;
					case IOC_INOUT:
						memcpy(msg.o.data, msg.i.data, msg.i.size < msg.o.size ? msg.i.size : msg.o.size);
						/* fallthrough */
					case IOC_OUT:
						buffer = msg.o.data;
						size = msg.o.size;
						break;
					case IOC_VOID:
					default:
						size = 0;
						buffer = NULL;
						break;
					}

					msg.o.io = error = ptm_ioctl(pty, msg.pid, msg.i.devctl, buffer);

					if (error > 0)
						error = EOK;
					break;
				}
				case mtGetAttr: {
					LOG_DEBUG("ptm getattr");
					switch (msg.i.attr) {
					case atEvents: {
						int *events = msg.o.data;
						error = EOK;
						*events = 0;

						if (pty->slave_open)
							*events |= POLLOUT;
						if (libtty_txready(&pty->tty)) {
							LOG_DEBUG("txready");
							*events |= POLLIN;
						}
						break;
					}
					default: {
						error = -EINVAL;
						LOG_DEBUG("ptm bad getattr: %d", msg.i.attr);
						break;
					}
					}
					break;
				}
				default: {
					LOG_DEBUG("ptm bad msg (%d)", msg.type);
					error = -EINVAL;
					break;
				}
				}
			}
			else {
				/* slave end */
				switch (msg.type) {
				case mtOpen: {
					LOG_DEBUG("pts open");
					msg.o.open = msg.object;
					if (!pty->master_open) {
						LOG_ERROR("opening slave whose master is closed");
						error = -ENXIO;
					} else if (pty->unlocked) {
						error = EOK;
						pty->slave_open += 1;
					}
					else {
						error = -EACCES;
					}
					break;
				}
				case mtClose: {
					LOG_DEBUG("pts close");
					pty->slave_open -= 1;

					if (!pty->slave_open)
						portEvent(pty_common.port, ptm_number(pty), POLLHUP);

					if (!pty->master_open && !pty->slave_open) {
						pty_destroy(pty);
					}

					error = EOK;
					break;
				}
				case mtWrite: {
					LOG_DEBUG("pts write");
					if (!pty->master_open) {
						/* return EPIPE */
						msg.o.io = 0;
						error = -EPIPE;
					}
					else if ((error = libtty_write(&pty->tty, msg.i.data, msg.i.size, O_NONBLOCK)) >= 0) {
						msg.o.io = error;
						error = error ? EOK : -EAGAIN;
					}
					break;
				}
				case mtRead: {
					LOG_DEBUG("pts read");
					if (!pty->master_open) {
						/* return EOF */
						msg.o.io = error = 0;
					}
					else if ((error = libtty_read(&pty->tty, msg.o.data, msg.o.size, O_NONBLOCK)) >= 0) {
						msg.o.io = error;
						error = error ? EOK : -EAGAIN;
					}
					break;
				}
				case mtDevCtl: {
					LOG_DEBUG("pts ioctl");
					void *out_arg = NULL;
					error = libtty_ioctl(&pty->tty, msg.pid, msg.i.devctl, msg.i.data, &out_arg);
					msg.o.io = error;
					if ((msg.i.devctl & IOC_OUT) && out_arg != NULL)
						memcpy(msg.o.data, out_arg, msg.o.size);
					break;
				}
				case mtGetAttr: {
					LOG_DEBUG("pts getattr");
					switch (msg.i.attr) {
					case atEvents: {
						error = EOK;
						int *events = msg.o.data;
						if (!pty->master_open)
							*events = POLLHUP;
						else
							*events = libtty_poll_status(&pty->tty);
						break;
					}
					default: {
						error = -EINVAL;
						LOG_DEBUG("pts bad getattr: %d", msg.i.attr);
						break;
					}
					}
					break;
				}
				default: {
					LOG_DEBUG("pts bad msg (%d)", msg.type);
					error = -EINVAL;
					break;
				}
				}
			}
			pty_unlock(pty);
		}

		msgRespond(pty_common.port, error, &msg, rid);
	}
}


int main(int argc, char **argv)
{
	int i;

	/* passed in by init program */
	pty_common.port = 3;

	mkdir("/dev/pts", 0755);

	if ((pty_common.devpts = open("/dev/pts", O_RDWR | O_DIRECTORY)) == -1) {
		LOG_ERROR("open /dev/pts");
		exit(EXIT_FAILURE);
	}

	mutexCreate(&pty_common.lock);

	/* Initialize pts array */
	memset(pty_common.pts, 0, sizeof(pty_common.pts));
	for (i = 0; i < sizeof(pty_common.pts) / sizeof(pty_common.pts[0]) - 1; ++i)
		pty_common.pts[i].freenext = pty_common.pts + i + 1;
	pty_common.freept = pty_common.pts;

	if (deviceCreate(-1, "/dev/ptmx", pty_common.port, (id_t)-1, S_IFCHR)) {
		LOG_ERROR("create ptmx device");
		exit(EXIT_FAILURE);
	}

	/* daemonize */
	if (fork()) _exit(0);

	msg_loop(NULL);
}
