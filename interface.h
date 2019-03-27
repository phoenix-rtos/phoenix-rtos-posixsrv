#ifndef _POSIXSRV_INTERFACE_H_
#define _POSIXSRV_INTERFACE_H_

#define POSIXSRV_CALLS(ID) \
	ID(read) \
	ID(write) \
	ID(open) \
	ID(close) \
	ID(dup) \
	ID(dup2) \
	ID(pipe) \


/*
	ID(link) \
	ID(unlink) \
	ID(ftruncate) \
	ID(lseek) \
	ID(mkfifo) \
	ID(chmod) \
	ID(fstat) \
	ID(accept) \
	ID(accept4) \
	ID(bind) \
	ID(connect) \
	ID(getpeername) \
	ID(getsockname) \
	ID(getsockopt) \
	ID(listen) \
	ID(recvfrom) \
	ID(sendto) \
	ID(socket) \
	ID(shutdown) \
	ID(setsockopt) \
	ID(ioctl) \
	ID(utimes) \
	ID(poll) \
	ID(setpgid) \
	ID(getpgid) \
	ID(setpgrp) \
	ID(getpgrp) \
	ID(setsid) \
	ID(fork) \
	ID(exec) \
*/

#define POSIXSRV_DEFINE_ENUM(name) posixsrv_##name,
enum {
	POSIXSRV_CALLS(POSIXSRV_DEFINE_ENUM)
	posixsrv_calls_count
};
#undef POSIXSRV_DEFINE_ENUM


typedef struct {
	int fd;
} posixsrv_dup_i_t;

typedef int posixsrv_dup_o_t;


typedef struct {
	int fd1;
	int fd2;
} posixsrv_dup2_i_t;

typedef ssize_t posixsrv_dup2_o_t;


typedef struct {
	int fd;
} posixsrv_write_i_t;

typedef ssize_t posixsrv_write_o_t;


typedef struct {
	int fd;
} posixsrv_read_i_t;

typedef ssize_t posixsrv_read_o_t;


typedef struct {
	int oflag;
	mode_t mode;
} posixsrv_open_i_t;

typedef int posixsrv_open_o_t;


typedef struct {
	int fd;
} posixsrv_close_i_t;

typedef int posixsrv_close_o_t;


typedef char posixsrv_pipe_i_t[0];

typedef struct {
	int retval;
	int fd[2];
} posixsrv_pipe_o_t;


#define POSIXSRV_INPUT_FIELD(name) posixsrv_##name##_i_t name;
typedef union {
	POSIXSRV_CALLS(POSIXSRV_INPUT_FIELD)
} posixsrv_i_t;
#undef POSIXSRV_INPUT_FIELD


#define POSIXSRV_OUTPUT_FIELD(name) posixsrv_##name##_o_t name;
typedef struct {
	int errno;

	union {
		POSIXSRV_CALLS(POSIXSRV_OUTPUT_FIELD)
	};
} posixsrv_o_t;
#undef POSIXSRV_OUTPUT_FIELD


#endif
