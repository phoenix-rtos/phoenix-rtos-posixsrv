#include <sys/types.h>
#include <sys/msg.h>
#include <sys/mman.h>

#include <errno.h>
#include <setjmp.h>

#include "interface.h"


int posixsrv_port = -1;


int px_connect(void)
{
	oid_t oid;
	int err;

	if ((err = lookup("/posixsrv", NULL, &oid)) < 0)
		return -err;

	posixsrv_port = oid.port;

	return EOK;
}


int px_init(void)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_init;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0)
		return -err;

	return _o->err_no;
}


int px_write(ssize_t *retval, int fd, const void *buf, size_t nbyte)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_write;

	msg.i.data = (void *)buf;
	msg.i.size = nbyte;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->write.fd = fd;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->write.retval;
	return _o->err_no;
}


int px_read(ssize_t *retval, int fd, void *buf, size_t nbyte)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_read;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = (void *)buf;
	msg.o.size = nbyte;

	_i->read.fd = fd;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->read.retval;
	return _o->err_no;
}


int px_open(int *retval, const char *path, int oflag, mode_t mode)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_open;

	msg.i.data = path;
	msg.i.size = strlen(path) + 1;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->open.oflag = oflag;
	_i->open.mode = mode;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->open.retval;
	return _o->err_no;
}


int px_close(ssize_t *retval, int fd)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_close;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->close.fd = fd;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->close.retval;
	return _o->err_no;
}


int px_recvfrom(ssize_t *retval, int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_recvfrom;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = buffer;
	msg.o.size = length;

	_i->recvfrom.socket = socket;
	_i->recvfrom.flags = flags;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	if (address != NULL) {
		*address_len = min(*address_len, _o->recvfrom.address_len);
		memcpy(address, _o->recvfrom.address, *address_len);
	}

	*retval = _o->recvfrom.retval;
	return _o->err_no;
}


int px_dup(ssize_t *retval, int fd)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_dup;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->dup.fd = fd;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->dup.retval;
	return _o->err_no;
}


int px_dup2(ssize_t *retval, int fd1, int fd2)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_dup2;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->dup2.fd1 = fd1;
	_i->dup2.fd2 = fd2;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->dup2.retval;
	return _o->err_no;
}


int px_pipe(int *retval, int fd[2])
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_pipe;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	fd[0] = _o->pipe.fd[0];
	fd[1] = _o->pipe.fd[1];

	*retval = _o->pipe.retval;
	return _o->err_no;
}


int px_mkfifo(int *retval, const char *pathname, mode_t mode)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_mkfifo;

	msg.i.data = pathname;
	msg.i.size = strlen(pathname) + 1;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->mkfifo.mode = mode;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->mkfifo.retval;
	return _o->err_no;
}


int px_execve(ssize_t *retval, const char *path, char *const argv[], char *const envp[])
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;
	int i;
	char *p;

	msg.type = posixsrv_execve;

	msg.i.size = strlen(path) + 1;

	if (argv != NULL) {
		for (i = 0; argv[i] != NULL; ++i)
			msg.i.size += strlen(argv[i]) + 1;
	}

	msg.i.size++;

	if (envp != NULL) {
		for (i = 0; envp[i] != NULL; ++i)
			msg.i.size += strlen(envp[i]) + 1;
	}

	if ((p = msg.i.data = mmap(NULL, (msg.i.size + SIZE_PAGE - 1) & ~(SIZE_PAGE - 1), PROT_READ | PROT_WRITE, MAP_NONE, NULL, -1)) == MAP_FAILED) {
		*retval = -1;
		return ENOMEM;
	}
	p = stpcpy(p, path) + 1;

	if (argv != NULL) {
		for (i = 0; argv[i] != NULL; ++i)
			p = stpcpy(p, argv[i]) + 1;
	}

	p = stpcpy(p, "") + 1;

	if (envp != NULL) {
		for (i = 0; envp[i] != NULL; ++i)
			p = stpcpy(p, envp[i]) + 1;
	}

	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	munmap(msg.i.data, (msg.i.size + SIZE_PAGE - 1) & (SIZE_PAGE - 1));
	*retval = _o->execve.retval;
	return _o->err_no;
}


int px_vfork(int *retval)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_vfork;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->vfork.retval;
	return _o->err_no;
}


static int vforked = 0;
extern jmp_buf _px_vfork_jmpbuf;


int px_do_vfork(void)
{
	int retval;
	int err;

	err = px_vfork(&retval);

	if (err != EOK) {
		errno = err;
		return -1;
	}

	vforked = retval;
	return 0;
}


int px_do_execve(const char *path, char *const argv[], char *const envp[])
{
	int retval;
	int err;

	err = px_execve(&retval, path, argv, envp);

	if (err != EOK) {
		errno = err;
		return -1;
	}

	if (vforked) {
		retval = vforked;
		vforked = 0;
		longjmp(_px_vfork_jmpbuf, retval);
	}

	/* exit */
	printf("execve without vfork\n");
	exit(0);
	return retval;
}


int px_exit(int status)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_exit;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->exit.status = status;

	if ((err = msgSend(posixsrv_port, &msg)) < 0)
		return -err;

	return _o->err_no;
}


int px_waitpid(pid_t *retval, pid_t pid, int *status, int options)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_waitpid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->waitpid.pid = pid;
	_i->waitpid.options = options;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	if (status != NULL)
		*status = _o->waitpid.status;

	*retval = _o->waitpid.retval;
	return _o->err_no;
}


int px_getpid(ssize_t *retval)
{
	int err;
	msg_t msg;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_getpid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->getpid.retval;
	return _o->err_no;
}


int px_ftruncate(int *retval, int fd, off_t length)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_ftruncate;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->ftruncate.fd = fd;
	_i->ftruncate.length = length;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->ftruncate.retval;
	return _o->err_no;
}


int px_unlink(int *retval, const char *path)
{
	int err;
	msg_t msg;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_unlink;

	msg.i.data = path;
	msg.i.size = strlen(path) + 1;

	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->unlink.retval;
	return _o->err_no;
}


int px_link(int *retval, const char *path1, const char *path2)
{
	int err;
	msg_t msg;
	posixsrv_o_t *_o = (void *)msg.o.raw;
	int len1, len2;

	msg.type = posixsrv_link;

	len1 = strlen(path1) + 1;
	len2 = strlen(path2) + 1;

	if ((msg.i.data = calloc(len1 + len2, 1)) == NULL) {
		*retval = -1;
		return -ENOMEM;
	}

	msg.i.size = len1 + len2;

	strcpy(msg.i.data, path1);
	strcpy(msg.i.data + len1, path2);

	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		_o->err_no = -err;
	}
	else {
		*retval = _o->link.retval;
	}

	free(msg.i.data);
	return _o->err_no;
}


int px_setsid(pid_t *retval)
{
	int err;
	msg_t msg;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_setsid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->setsid.retval;
	return _o->err_no;
}


int px_setpgid(pid_t *retval, pid_t pid, pid_t pgid)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_setpgid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->setpgid.pid = pid;
	_i->setpgid.pgid = pgid;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->setpgid.retval;
	return _o->err_no;
}


int px_getsid(pid_t *retval, pid_t pid)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_getsid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->getsid.pid = pid;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->getsid.retval;
	return _o->err_no;
}


int px_getpgid(pid_t *retval, pid_t pid)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_getpgid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->getpgid.pid = pid;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->getpgid.retval;
	return _o->err_no;
}


int px_getppid(pid_t *retval, pid_t pid)
{
	int err;
	msg_t msg;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_getppid;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->getppid.retval;
	return _o->err_no;
}


int px_lseek(off_t *retval, int fd, off_t offset, int whence)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_lseek;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->lseek.fd = fd;
	_i->lseek.offset = offset;
	_i->lseek.whence = whence;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->lseek.retval;
	return _o->err_no;
}



int px_fstat(int *retval, int fd, struct stat *buf)
{
	int err;
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_fstat;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = buf;
	msg.o.size = sizeof(*buf);

	_i->fstat.fd = fd;

	if ((err = msgSend(posixsrv_port, &msg)) < 0) {
		*retval = -1;
		return -err;
	}

	*retval = _o->fstat.retval;
	return _o->err_no;
}
