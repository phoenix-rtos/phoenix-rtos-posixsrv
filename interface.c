#include "sys/types.h"
#include "sys/msg.h"
#include "interface.h"

#define POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
static inline int posixsrv_##NAME ARGS \
{ \
	msg_t msg; \
	posixsrv_i_t *_i = (void *)msg.i.raw; \
	posixsrv_o_t *_o = (void *)msg.o.raw; \
	msg.i.data = IDATA; \
	msg.i.size = ISIZE; \
	msg.o.data = ODATA; \
	msg.o.size = OSIZE;


#define POSIXSRV_CALL_POST(NAME, RETACCESS) \
	*retval = _o->retval.NAME RETACCESS; \
	return _o->errno; \
}


#define DEF_POSIXSRV_CALL00(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, RETACCESS) \
static inline int posixsrv_##NAME ARGS \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	msgSend(posixsrv_port, &msg); \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL10(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, RETACCESS) \
static inline int posixsrv_##NAME ARGS \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	_i->NAME.ARG1 = ARG1; \
	msgSend(posixsrv_port, &msg); \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL20(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, ARG2, RETACCESS) \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	_i->NAME.ARG1 = ARG1; \
	_i->NAME.ARG1 = ARG2; \
	msgSend(posixsrv_port, &msg); \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


#define DEF_POSIXSRV_CALL02(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE, ARG1, ARG2, RETACCESS) \
static inline int posixsrv_##NAME ARGS \
	POSIXSRV_CALL_PRE(NAME, ARGS, IDATA, ISIZE, ODATA, OSIZE) \
	msgSend(posixsrv_port, &msg); \
	_o->NAME.ARG1 = ARG1; \
	_o->NAME.ARG1 = ARG2; \
	POSIXSRV_CALL_POST(NAME, RETACCESS)


static int posixsrv_port = -1;


DEF_POSIXSRV_CALL10(write, (int fd, const void *buf, size_t nbyte, ssize_t *retval), buf, nbyte, NULL, 0, fd, )

DEF_POSIXSRV_CALL10(read, (int fd, void *buf, size_t nbyte, ssize_t *retval), NULL, 0, buf, nbyte, fd, )

DEF_POSIXSRV_CALL20(open, (const char *path, int oflag, mode_t mode, int *retval), path, strlen(path) + 1, NULL, 0, oflag, mode, )

DEF_POSIXSRV_CALL10(close, (int fd, int *retval), NULL, 0, NULL, 0, fd, )

DEF_POSIXSRV_CALL02(pipe, (int fildes[2], int *retval), NULL, 0, NULL, 0, fd[0], fd[1], .retval)

DEF_POSIXSRV_CALL20(dup2, (int fd1, int fd2, int *retval), NULL, 0, NULL, 0, fd1, fd2, )

