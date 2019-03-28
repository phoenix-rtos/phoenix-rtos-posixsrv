#include <sys/types.h>
#include <sys/msg.h>

#include <errno.h>

#include "interface.h"


static int posixsrv_port = -1;


int sys_write(ssize_t *retval, int fd, const void *buf, size_t nbyte)
{
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_write;

	msg.i.data = (void *)buf;
	msg.i.size = nbyte;
	msg.o.data = NULL;
	msg.o.size = 0;

	_i->write.fd = fd;

	if (msgSend(posixsrv_port, &msg) < 0) {
		*retval = -1;
		return EIO;
	}

	*retval = _o->write.retval;
	return _o->errno;
}


int sys_read(ssize_t *retval, int fd, void *buf, size_t nbyte)
{
	msg_t msg;
	posixsrv_i_t *_i = (void *)msg.i.raw;
	posixsrv_o_t *_o = (void *)msg.o.raw;

	msg.type = posixsrv_read;

	msg.i.data = NULL;
	msg.i.size = 0;
	msg.o.data = (void *)buf;
	msg.o.size = nbyte;

	_i->read.fd = fd;

	if (msgSend(posixsrv_port, &msg) < 0) {
		*retval = -1;
		return EIO;
	}

	*retval = _o->read.retval;
	return _o->errno;
}


int sys_open(ssize_t *retval, const char *path, int oflag, mode_t mode)
{
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

	if (msgSend(posixsrv_port, &msg) < 0) {
		*retval = -1;
		return EIO;
	}

	*retval = _o->open.retval;
	return _o->errno;
}


int sys_recvfrom(ssize_t *retval, int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len)
{
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

	if (msgSend(posixsrv_port, &msg) < 0) {
		*retval = -1;
		return EIO;
	}

	if (address != NULL) {
		*address_len = min(*address_len, _o->recvfrom.address_len);
		memcpy(address, _o->recvfrom.address, *address_len);
	}

	*retval = _o->recvfrom.retval;
	return _o->errno;
}


#if 0
#define POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
static inline int sys_##NAME ARGS \
{ \
	int err; \
	msg_t msg; \
	posixsrv_i_t *_i __attribute__((unused)) = (void *)msg.i.raw; \
	posixsrv_o_t *_o = (void *)msg.o.raw; \
	msg.i.data = (void *)IDATA; \
	msg.i.size = ISIZE; \
	msg.o.data = ODATA; \
	msg.o.size = OSIZE;


#define POSIXSRV_SEND \
	if ((err = msgSend(posixsrv_port, &msg)) < 0) { \
		*retval = -1; \
		return EIO; \
	}


#define POSIXSRV_CALL_POST(NAME, RETACCESS) \
	*retval = _o->NAME RETACCESS; \
	return _o->errno; \
}


#define DEF_POSIXSRV_CALL00(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, RETACCESS) \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	POSIXSRV_SEND \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL10(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, RETACCESS) \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	_i->NAME.ARG1 = ARG1; \
	POSIXSRV_SEND \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL20(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, ARG2, RETACCESS) \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	_i->NAME.ARG1 = ARG1; \
	_i->NAME.ARG1 = ARG2; \
	POSIXSRV_SEND \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL02(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, ARG2, RETACCESS) \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	POSIXSRV_SEND \
	_o->NAME.ARG1 = ARG1; \
	_o->NAME.ARG1 = ARG2; \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


static int posixsrv_port = -1;


void posixsrv_init(void)
{
	oid_t oid;

	if (!lookup("posixsrv", NULL, &oid))
		posixsrv_port = oid.port;
}


DEF_POSIXSRV_CALL10(write, (int fd, const void *buf, size_t nbyte, ssize_t *retval), buf, nbyte, NULL, 0, fd, )

DEF_POSIXSRV_CALL10(read, (int fd, void *buf, size_t nbyte, ssize_t *retval), NULL, 0, buf, nbyte, fd, )

DEF_POSIXSRV_CALL20(open, (const char *path, int oflag, mode_t mode, int *retval), path, strlen(path) + 1, NULL, 0, oflag, mode, )

DEF_POSIXSRV_CALL10(close, (int fd, int *retval), NULL, 0, NULL, 0, fd, )

DEF_POSIXSRV_CALL02(pipe, (int fd[2], int *retval), NULL, 0, NULL, 0, fd[0], fd[1], .retval)

DEF_POSIXSRV_CALL20(dup2, (int fd1, int fd2, int *retval), NULL, 0, NULL, 0, fd1, fd2, )
#endif
