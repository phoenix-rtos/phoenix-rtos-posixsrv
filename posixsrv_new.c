/*
 * Phoenix-RTOS
 *
 * POSIX-compatibility module
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <sys/msg.h>
#include <sys/rb.h>
#include <sys/threads.h>
#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>

#include "posix/idtree.h"
#include "interface.h"
#include "posixsrv.h"


struct {
	handle_t lock;
	pid_t nextpid;
	idtree_t processes;
} posixsrv_common;


/* Process functions */

static void common_lock(void)
{
	while (mutexLock(posixsrv_common.lock) < 0) ;
}


static void common_unlock(void)
{
	mutexUnlock(posixsrv_common.lock);
}


static void process_lock(process_t *p)
{
	while (mutexLock(p->lock) < 0) ;
}


static void process_unlock(process_t *p)
{
	mutexUnlock(p->lock);
}


static process_t *process_new(void)
{
	process_t *p;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return NULL;

	common_lock();
	p->pid = posixsrv_common.nextpid;
	idtree_alloc(&posixsrv_common.processes, &p->linkage);
	if ((posixsrv_common.nextpid = p->pid + 1) > POSIXSRV_MAX_PID)
		posixsrv_common.nextpid = 1;
	common_unlock();

	return p;
}


static void process_destroy(process_t *p)
{
	idtree_remove(&posixsrv_common.processes, &p->linkage);
	free(p);
}


static process_t *process_find(pid_t pid)
{
	process_t *p;

	common_lock();
	if ((p = lib_treeof(process_t, linkage, idtree_find(&posixsrv_common.processes, pid))) != NULL)
		p->refs++;
	common_unlock();

	return p;
}


static void process_put(process_t *p)
{
	common_lock();
	if (!--p->refs)
		process_destroy(p);
	common_unlock();
}


/* File functions */

static void file_lock(file_t *f)
{
	while (mutexLock(f->lock) < 0) ;
}


static void file_unlock(file_t *f)
{
	mutexUnlock(f->lock);
}


static void file_destroy(file_t *f)
{
	resourceDestroy(f->lock);
	free(f);
}


static int fd_alloc(process_t *p, int fd)
{
	while (fd++ < p->fdcount) {
		if (p->fds[fd].file == NULL)
			return fd;
	}

	return -1;
}


static int file_new(process_t *p, int fd)
{
	file_t *f;

	if ((fd = fd_alloc(p, fd)) < 0)
		return -ENFILE;

	if ((f = p->fds[fd].file = malloc(sizeof(file_t))) == NULL)
		return -ENOMEM;

	memset(f, 0, sizeof(file_t));
	mutexCreate(&f->lock);
	f->refs = 1;
	f->offset = 0;
	return fd;
}


static void file_ref(file_t *f)
{
	file_lock(f);
	++f->refs;
	file_unlock(f);
}


static void file_deref(file_t *f)
{
	file_lock(f);
	if (!--f->refs)
		file_destroy(f);
	else
		file_unlock(f);
}


static void fd_unused(process_t *p, int fd)
{
	file_destroy(p->fds[fd].file);
	p->fds[fd].file = NULL;
}


static file_t *file_get(process_t *p, int fd)
{
	file_t *f;

	if (fd < 0 || fd >= p->fdcount || (f = p->fds[fd].file) == NULL)
		return NULL;

	file_ref(f);
	return f;
}


/* File operation wrappers */

#define POSIX_RET(val, err) return *retval = val, err

static int posix_write(process_t *p, int fd, void *buf, size_t nbyte, ssize_t *retval)
{
	int errno;
	file_t *f;

	if ((f = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	errno = f->ops->write(f, retval, buf, nbyte);
	file_deref(f);
	return errno;
}


static int posix_read(process_t *p, int fd, void *buf, size_t nbyte, ssize_t *retval)
{
	file_t *f;

	if ((f = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	errno = f->ops->read(f, retval, buf, nbyte);
	file_deref(f);
	return errno;
}


static int posix_open(process_t *p, char *path, int oflag, mode_t mode, ssize_t *retval)
{
	return EOK;
}


static int posix_close(process_t *p, int fd, ssize_t *retval)
{
	return EOK;
}


/* Other */

static int posix_pipe(process_t *p, int fd[2], ssize_t *retval)
{
	return EOK;
}


static int _posix_dup(process_t *p, int fd, int *retval)
{
	int newfd;
	file_t *f;

	if (fd < 0 || fd >= p->fdcount)
		POSIX_RET(-1, EBADF);

	if ((newfd = fd_alloc(p, fd)) < 0)
		POSIX_RET(-1, EMFILE);

	if ((f = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	p->fds[newfd].file = f;
	p->fds[newfd].flags = 0;

	POSIX_RET(newfd, EOK);
}


static int posix_dup(process_t *p, int fd, int *retval)
{
	int errno;

	process_lock(p);
	errno = _posix_dup(p, fd, retval);
	process_unlock(p);
	return errno;
}


static int _posix_dup2(process_t *p, int fd, int fd2, int *retval)
{
	file_t *f, *f2;

	if (fd == fd2)
		POSIX_RET(fd, EOK);

	if (fd2 < 0 || fd2 > p->fdcount)
		POSIX_RET(-1, EBADF);
		return *retval = -1, EBADF;

	if ((f = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	if ((f2 = p->fds[fd2].file) != NULL)
		file_deref(f2);

	p->fds[fd2].file = f;
	p->fds[fd2].flags = 0;

	POSIX_RET(fd2, EOK);
}


static int posix_dup2(process_t *p, int fd1, int fd2, int *retval)
{
	int errno;

	process_lock(p);
	errno = _posix_dup2(p, fd1, fd2, retval);
	process_unlock(p);
	return errno;
}


/* Generic operations for external files */

static ssize_t posix_genericWrite(file_t *file, void *data, size_t size)
{
	return 0;
}


/* Handler functions */


static int handle_write(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int fd = _i->write.fd;
	void *data = msg->i.data;
	size_t size = msg->i.size;
	ssize_t *retval = &_o->write;

	_o->errno = posix_write(p, fd, data, size, retval);
	return EOK;
}


static int handle_read(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int fd = _i->read.fd;
	void *data = msg->o.data;
	size_t size = msg->o.size;
	ssize_t *retval = &_o->read;

	_o->errno = posix_read(p, fd, data, size, retval);
	return EOK;
}


static int handle_open(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int oflag = _i->open.oflag;
	mode_t mode = _i->open.mode;
	char *path = msg->i.data;
	int *retval = &_o->open;

	_o->errno = posix_open(p, path, oflag, mode, retval);
	return EOK;
}


static int handle_close(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int fd = _i->close.fd;
	ssize_t *retval = &_o->close;

	_o->errno = posix_close(p, fd, retval);
	return EOK;
}


static int handle_pipe(process_t *p, msg_t *msg)
{
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int *fd = _o->pipe.fd;
	int *retval = &_o->pipe.retval;

	_o->errno = posix_pipe(p, fd, retval);
	return EOK;
}


static int handle_dup(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int fd = _i->dup.fd;
	int *retval = &_o->dup;

	_o->errno = posix_dup(p, fd, retval);
	return EOK;
}


static int handle_dup2(process_t *p, msg_t *msg)
{
	posixsrv_i_t *_i = (void *)msg->i.raw;
	posixsrv_o_t *_o = (void *)msg->o.raw;

	int fd1 = _i->dup2.fd1;
	int fd2 = _i->dup2.fd2;
	int *retval = &_o->dup2;

	_o->errno = posix_dup2(p, fd1, fd2, retval);
	return EOK;
}



/* Interface threads */

int posixsrv_handleMsg(msg_t *msg)
{
	int err;
	process_t *process;

	if ((process = process_find(msg->pid)) == NULL)
		return -EINVAL;

#define POSIXSRV_CASE(name) \
	case posixsrv_##name: err = handle_##name(process, msg); break;

	switch (msg->type) {
		POSIXSRV_CALLS(POSIXSRV_CASE)
		default:
			err = -EINVAL;
			break;
	}

#undef POSIXSRV_CASE

	process_put(process);
	return err;
}


static void posixsrv_poolThread(void *arg)
{
	pool_t *pool = arg;
	msg_t msg;
	unsigned rid;

	for (;;) {
		rid = 0;

		mutexLock(pool->lock);
		pool->free++;

		while (pool->msg != NULL)
			condWait(pool->full, pool->lock, 0);

		pool->msg = &msg;
		pool->rid = &rid;

		condSignal(pool->empty);

		while (!rid)
			condWait(pool->empty, pool->lock, 0);

		pool->free--;
		mutexUnlock(pool->lock);

		priority(msg.priority);
		posixsrv_handleMsg(&msg);
		priority(pool->priority);

		msgRespond(pool->port, &msg, rid);
	}
}


static void posixsrv_msgThread(void *arg)
{
	pool_t *pool = arg;
	msg_t *msg = NULL;
	unsigned *rid = NULL;

	for (;;) {
		mutexLock(pool->lock);
		while ((msg = pool->msg) == NULL) {
			/* TODO: spawn new thread */
			condWait(pool->empty, pool->lock, 0);
		}
		rid = pool->rid;

		pool->msg = NULL;
		pool->rid = NULL;

		mutexUnlock(pool->lock);
		condSignal(pool->full);

		if (msgRecv(pool->port, msg, rid) < 0)
			continue;

		condSignal(pool->empty);
	}
}


int main(int argc, char **argv)
{
	return 0;
}