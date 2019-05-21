#ifndef _POSIXSRV_INTERFACE_H_
#define _POSIXSRV_INTERFACE_H_

#include <sys/socket.h>

#define POSIXSRV_CALLS(ID) \
	ID(read) \
	ID(write) \
	ID(open) \
	ID(close) \
	ID(dup) \
	ID(dup2) \
	ID(pipe) \
	ID(recvfrom) \
	ID(execve) \
	ID(vfork) \
	ID(exit) \
	ID(waitpid) \
	ID(getpid)


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
	posixsrv_init = 0x1000,
	POSIXSRV_CALLS(POSIXSRV_DEFINE_ENUM)
	posixsrv_calls_count
};
#undef POSIXSRV_DEFINE_ENUM


typedef struct {
	int fd;
} posixsrv_dup_i_t;

typedef struct {
	int retval;
} posixsrv_dup_o_t;


typedef struct {
	int fd1;
	int fd2;
} posixsrv_dup2_i_t;

typedef struct {
	ssize_t retval;
} posixsrv_dup2_o_t;


typedef struct {
	int fd;
} posixsrv_write_i_t;

typedef struct {
	ssize_t retval;
} posixsrv_write_o_t;


typedef struct {
	int fd;
} posixsrv_read_i_t;

typedef struct {
	ssize_t retval;
} posixsrv_read_o_t;


typedef struct {
	int oflag;
	mode_t mode;
} posixsrv_open_i_t;

typedef struct {
	int retval;
} posixsrv_open_o_t;


typedef struct {
	int fd;
} posixsrv_close_i_t;

typedef struct {
	int retval;
} posixsrv_close_o_t;


typedef char posixsrv_pipe_i_t[0];

typedef struct {
	int retval;
	int fd[2];
} posixsrv_pipe_o_t;


typedef struct {
	int socket;
	int flags;
} posixsrv_recvfrom_i_t;

typedef struct {
	int retval;
	socklen_t address_len;
	struct sockaddr address[];
} posixsrv_recvfrom_o_t;


typedef char posixsrv_execve_i_t[0];

typedef struct {
	int retval;
} posixsrv_execve_o_t;


typedef char posixsrv_vfork_i_t[0];

typedef struct {
	int retval;
} posixsrv_vfork_o_t;


typedef struct {
	int status;
} posixsrv_exit_i_t;

typedef char posixsrv_exit_o_t[0];


typedef struct {
	pid_t pid;
	int options;
} posixsrv_waitpid_i_t;

typedef struct {
	pid_t retval;
	int status;
} posixsrv_waitpid_o_t;


typedef char posixsrv_getpid_i_t[0];

typedef struct {
	pid_t retval;
} posixsrv_getpid_o_t;


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
