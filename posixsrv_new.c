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

#include "posixsrv.h"


static int fd_alloc(process_t *p, int fd)
{
	while (fd++ < p->fdcount) {
		if (p->fds[fd].file == NULL)
			return fd;
	}

	return -1;
}


static void file_lock(file_t *f)
{
	while (mutexLock(f->lock) < 0) ;
}


static void file_unlock(file_t *f)
{
	mutexUnlock(f->lock);
}


static void file_ref(file_t *f)
{
	file_lock(f);
	++f->refs;
	file_unlock(f);
}


static void file_destroy(file_t *f)
{
	mutexDestroy(f->lock);
	free(f);
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


static int file_new(process_t *p, int fd)
{
	file_t *f;

	if ((fd = fd_alloc(fd)) < 0)
		return set_errno(p, -ENFILE);

	if ((f = p->fds[fd].file = malloc(sizeof(file_t))) == NULL)
		return set_errno(p, -ENOMEM);

	hal_memset(f, 0, sizeof(file_t));
	proc_lockInit(&f->lock);
	f->refs = 1;
	f->offset = 0;
	return fd;
}


/* File operation wrappers */

static ssize_t posix_write(process_t *p, int fd, void *buf, size_t nbyte)
{
	ssize_t rv;
	file_t *f;

	if ((f = file_get(p, fd)) == NULL)
		return -EBADF;

	rv = p->ops->write(f, buf, nbyte);
	file_deref(f);
	return rv;
}


static ssize_t posix_read(process_t *p, int fd, void *buf, size_t nbyte)
{
	ssize_t rv;
	file_t *f;

	if ((f = file_get(p, fd)) == NULL)
		return -EBADF;

	rv = p->ops->read(f, buf, nbyte);
	file_deref(f);
	return rv;
}


static off_t posix_lseek(process_t *p, int fildes, off_t offset, int whence)
{
	file_t *f;
	off_t rv;
	size_t sz;

	if ((f = file_get(p, fd)) == NULL)
		return set_errno(p, -EBADF);

	rv = p->ops->lseek(f, offset, whence);
	file_deref(f);
	return rv;
}


/* Other */

static int _posix_dup(process_t *p, int fildes)
{
	int newfd;
	file_t *f;

	if (fildes < 0 || fildes >= p->fdcount)
		return set_errno(p, -EBADF);

	if ((newfd = fd_alloc(p, fildes)) < 0)
		return set_errno(p, -EMFILE);

	if ((f = file_get(p, fildes)) == NULL)
		return set_errno(p, -EBADF);

	p->fds[newfd].file = f;
	p->fds[newfd].flags = 0;
	return newfd;
}


static int _posix_dup2(process_t *p, int fildes, int fildes2)
{
	file_t *f, *f2;

	if (fildes == fildes2)
		return fildes;

	if (fildes2 < 0 || fildes2 > p->maxfd)
		return set_errno(p, -EBADF);

	if ((f = file_get(p, fildes)) == NULL)
		return set_errno(p, -EBADF);

	if ((f2 = p->fds[fildes2].file) != NULL)
		file_deref(f2);

	p->fds[fildes2].file = f;
	p->fds[fildes2].flags = 0;
	return fildes2;
}


/* Generic operations for external files */

static ssize_t posix_genericWrite(file_t *file, void *data, size_t size)
{

}