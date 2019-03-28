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
	unsigned port;
	pid_t nextpid;

	handle_t plock;
	idtree_t processes;

	handle_t nlock;
	idtree_t nodes;

	node_t zero;
	node_t null;

	long long stacks[4][0x400];
} posixsrv_common;


/* Process functions */

static void proctree_lock(void)
{
	while (mutexLock(posixsrv_common.plock) < 0) ;
}


static void proctree_unlock(void)
{
	mutexUnlock(posixsrv_common.plock);
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

	proctree_lock();
	p->pid = posixsrv_common.nextpid;
	idtree_alloc(&posixsrv_common.processes, &p->linkage);
	if ((posixsrv_common.nextpid = p->pid + 1) > POSIXSRV_MAX_PID)
		posixsrv_common.nextpid = 1;
	proctree_unlock();

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

	proctree_lock();
	if ((p = lib_treeof(process_t, linkage, idtree_find(&posixsrv_common.processes, pid))) != NULL)
		p->refs++;
	proctree_unlock();

	return p;
}


static void process_put(process_t *p)
{
	proctree_lock();
	if (!--p->refs)
		process_destroy(p);
	proctree_unlock();
}


/* Generic operations for files */

static int generic_open(file_t *file)
{
	msg_t msg;

	msg.i.data = msg.o.data = NULL;
	msg.i.size = msg.o.size = 0;

	msg.type = mtOpen;
	msg.i.openclose.oid = file->oid;
	msg.i.openclose.flags = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err)
		return EIO;

	return EOK;
}


static int generic_close(file_t *file)
{
	msg_t msg;

	msg.i.data = msg.o.data = NULL;
	msg.i.size = msg.o.size = 0;

	msg.type = mtClose;
	msg.i.openclose.oid = file->oid;
	msg.i.openclose.flags = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err)
		return EIO;

	return EOK;
}


static int generic_write(file_t *file, ssize_t *retval, void *data, size_t size)
{
	msg_t msg;

	msg.i.data = data;
	msg.i.size = size;

	msg.o.data = NULL;
	msg.o.size = 0;

	msg.type = mtWrite;
	msg.i.io.oid = file->oid;
	msg.i.io.offs = file->offset;
	msg.i.io.mode = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err)
		return EIO;

	return EOK;
}


static int generic_read(file_t *file, ssize_t *retval, void *data, size_t size)
{
	msg_t msg;

	msg.i.data = data;
	msg.i.size = size;

	msg.o.data = NULL;
	msg.o.size = 0;

	msg.type = mtRead;
	msg.i.io.oid = file->oid;
	msg.i.io.offs = file->offset;
	msg.i.io.mode = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err)
		return EIO;

	return EOK;
}


const static file_ops_t generic_ops = {
	.open = generic_open,
	.close = generic_close,
	.read = generic_read,
	.write = generic_write
};


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


/* File descriptor table functions */

static int _fd_alloc(process_t *p, int fd)
{
	while (fd++ < p->fdcount) {
		if (p->fds[fd].file == NULL)
			return fd;
	}

	return -1;
}


static int _file_new(process_t *p, oid_t *oid, int *fd)
{
	file_t *f;

	if ((*fd = _fd_alloc(p, *fd)) < 0)
		return ENFILE;

	if ((f = p->fds[*fd].file = malloc(sizeof(file_t))) == NULL)
		return ENOMEM;

	memset(f, 0, sizeof(file_t));
	mutexCreate(&f->lock);
	f->refs = 1;
	f->offset = 0;
	f->mode = 0;
	f->status = 0;

	return EOK;
}


static file_t *_file_get(process_t *p, int fd)
{
	file_t *f;

	if (fd < 0 || fd >= p->fdcount || (f = p->fds[fd].file) == NULL)
		return NULL;

	file_ref(f);
	return f;
}


static int _file_close(process_t *p, int fd)
{
	if (fd < 0 || fd >= p->fdcount || p->fds[fd].file == NULL)
		return EBADF;

	file_deref(p->fds[fd].file);
	p->fds[fd].file = NULL;
	return EOK;
}


static int file_new(process_t *p, oid_t *oid, int *fd)
{
	int errno;
	process_lock(p);
	errno = _file_new(p, oid, fd);
	process_unlock(p);
	return errno;
}


static file_t *file_get(process_t *p, int fd)
{
	file_t *f;
	process_lock(p);
	f = _file_get(p, fd);
	process_unlock(p);
	return f;
}


static int file_close(process_t *p, int fd)
{
	int errno;
	process_lock(p);
	errno = _file_close(p, fd);
	process_unlock(p);
	return errno;
}


/* Internal files */

static void nodetree_lock(void)
{
	while (mutexLock(posixsrv_common.nlock) < 0) ;
}


static void nodetree_unlock(void)
{
	mutexUnlock(posixsrv_common.nlock);
}


node_t *node_get(oid_t *oid)
{
	node_t *node;

	if (oid->port != posixsrv_common.port)
		return NULL;

	nodetree_lock();
	node = lib_treeof(node_t, linkage, idtree_find(&posixsrv_common.nodes, oid->id));
	nodetree_unlock();

	return node;
}


#define POSIX_RET(val, err) return *retval = val, err

/* /dev/zero */

static int zero_open(file_t *file)
{
	return EOK;
}


static int zero_close(file_t *file)
{
	return EOK;
}


static int zero_write(file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(size, EOK);
}


static int zero_read(file_t *file, ssize_t *retval, void *data, size_t size)
{
	memset(data, 0, size);
	POSIX_RET(size, EOK);
}


static const file_ops_t zero_ops = {
	.open = zero_open,
	.close = zero_close,
	.read = zero_read,
	.write = zero_write
};


/* /dev/null */

static int null_open(file_t *file)
{
	return EOK;
}


static int null_close(file_t *file)
{
	return EOK;
}


static int null_write(file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(size, EOK);
}


static int null_read(file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(0, EOK);
}


static const file_ops_t null_ops = {
	.open = null_open,
	.close = null_close,
	.read = null_read,
	.write = null_write
};


/* /dev/ptmx */
#if 0
static int ptmx_open(file_t *file)
{
	if ((file->node = pty_new()) == NULL)
		return ENOMEM;

	return EOK;
}
#endif

/* File operation wrappers */


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


static int posix_open(process_t *p, char *path, int oflag, mode_t mode, int *retval)
{
	oid_t oid;
	int errno, fd = 0;
	file_t *file;

	/* TODO: canonicalize path */
	if (lookup(path, NULL, &oid) < 0)
		POSIX_RET(-1, ENOENT);

	if ((errno = file_new(p, &oid, &fd)))
		POSIX_RET(-1, errno);

	file = file_get(p, fd);

	file_lock(file);
	if ((file->node = node_get(&oid)) != NULL)
		file->ops = file->node->ops;
	else
		file->ops = &generic_ops;

	file->oid = oid;
	file_unlock(file);

	if ((errno = file->ops->open(file))) {
		file_close(p, fd);
		fd = -1;
	}

	file_deref(file);
	POSIX_RET(fd, errno);
}


static int posix_close(process_t *p, int fd, int *retval)
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

	if ((newfd = _fd_alloc(p, fd)) < 0)
		POSIX_RET(-1, EMFILE);

	if ((f = _file_get(p, fd)) == NULL)
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

	if ((f = _file_get(p, fd)) == NULL)
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


/* Threadpool functions */

static void pool_lock(pool_t *pool)
{
	while (mutexLock(pool->lock) < 0) ;
}


static void pool_unlock(pool_t *pool)
{
	mutexUnlock(pool->lock);
}


static void pool_waitEmpty(pool_t *pool)
{
	condWait(pool->empty, pool->lock, 0);
}


static void pool_waitFull(pool_t *pool)
{
	condWait(pool->full, pool->lock, 0);
}


static void posixsrv_poolThread(void *arg)
{
	pool_t *pool = arg;
	msg_t msg;
	unsigned rid;

	pool_lock(pool);
	pool->count++;
	pool_unlock(pool);

	for (;;) {
		rid = 0;

		pool_lock(pool);
		pool->free++;

		while (pool->msg != NULL)
			pool_waitFull(pool);

		pool->msg = &msg;
		pool->rid = &rid;

		condSignal(pool->empty);

		while (!rid)
			pool_waitEmpty(pool);

		pool->free--;
		pool_unlock(pool);

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
		pool_lock(pool);
		while ((msg = pool->msg) == NULL) {
			/* TODO: spawn new thread */
			pool_waitEmpty(pool);
		}
		rid = pool->rid;

		pool->msg = NULL;
		pool->rid = NULL;

		pool_unlock(pool);
		condSignal(pool->full);

		if (msgRecv(pool->port, msg, rid) < 0)
			continue;

		condSignal(pool->empty);
	}
}


static void posixsrv_init(void)
{
	portCreate(&posixsrv_common.port);
	idtree_init(&posixsrv_common.processes);
	mutexCreate(&posixsrv_common.plock);
	mutexCreate(&posixsrv_common.nlock);
}


static void pool_init(pool_t *pool, unsigned port)
{
	mutexCreate(&pool->lock);
	condCreate(&pool->full);
	condCreate(&pool->empty);
	pool->priority = 1;
	pool->max = pool->min = sizeof(posixsrv_common.stacks) / sizeof(posixsrv_common.stacks[0]);
	pool->free = 0;
	pool->count = 0;
	pool->port = port;
	pool->rid = NULL;
	pool->msg = NULL;
}


static void special_init(void)
{
	idtree_init(&posixsrv_common.nodes);

	posixsrv_common.zero.ops = &zero_ops;
	idtree_alloc(&posixsrv_common.nodes, &posixsrv_common.zero.linkage);

	posixsrv_common.null.ops = &null_ops;
	idtree_alloc(&posixsrv_common.nodes, &posixsrv_common.null.linkage);
}


int main(int argc, char **argv)
{
	pool_t pool;
	int i;

	posixsrv_init();
	special_init();
	pool_init(&pool, posixsrv_common.port);

	for (i = 0; i < pool.min; ++i)
		beginthread(posixsrv_poolThread, pool.priority, posixsrv_common.stacks[i], sizeof(posixsrv_common.stacks[i]), &pool);

	priority(pool.priority);
	posixsrv_msgThread(&pool);
	return 0;
}