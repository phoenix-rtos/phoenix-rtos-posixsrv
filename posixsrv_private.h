/*
 * Phoenix-RTOS
 *
 * posixsrv_private.h
 *
 * Copyright 2018 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef POSIXSRV_PRIVATE_H
#define POSIXSRV_PRIVATE_H

#include <sys/ioctl.h>
#include <termios.h>
#include <posix/utils.h>
#include <posix/idtree.h>
#include <libtty.h>
#include <syslog.h>

#define PIPE_BUFSZ 0x1000

#define log_sev(sev, fmt, ...) syslog(sev, __FILE__ ":%d %s: " fmt, __LINE__, __func__, ##__VA_ARGS__)
#define log_debug(fmt, ...) log_sev(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  log_sev(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  log_sev(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_sev(LOG_ERR, fmt, ##__VA_ARGS__)

typedef struct request_t {
	struct request_t *next, *prev;
	rbnode_t linkage;
	unsigned port;

	struct _object_t *object;
	time_t wakeup;
	msg_rid_t rid;
	msg_t msg;

	/* Subsystem specific per-request state */
	union {
		libtty_read_state_t pts_read;
	};
} request_t;


struct _object_t;


typedef request_t *(handler_t)(struct _object_t *, request_t *);


struct _pipe_t;


typedef struct {
	union {
		struct {
			handler_t *open, *close, *read, *write, *truncate, *devctl,
				*create, *destroy, *setattr, *getattr,
				*lookup, *link, *unlink, *readdir;
			void (*release)(struct _object_t *);
			void (*timeout)(request_t *);
		};
		handler_t *handlers[mtCount + 2];
	};
} operations_t;


typedef struct _object_t {
	idnode_t linkage;
	const operations_t *operations;
	int refs, destroy;
} object_t;


static inline int rq_sz(request_t *r)
{
	return (r->msg.type == mtWrite) ? r->msg.i.size : r->msg.o.size;
}


static inline void *rq_buf(request_t *r)
{
	return (r->msg.type == mtWrite) ? r->msg.i.data : r->msg.o.data;
}


extern void rq_wakeup(request_t *r);


extern void rq_setResponse(request_t *r, int retval);


extern void rq_timeout(request_t *r, int timeout);


extern int rq_id(request_t *r);


extern unsigned srv_port(void);


extern int object_link(object_t *o, const char *path);


static inline int object_id(object_t *o)
{
	return o->linkage.id;
}


extern void object_destroy(object_t *o);


extern object_t *object_get(int id);


extern void object_ref(object_t *o);


extern void object_put(object_t *o);


extern int object_create(object_t *o, const operations_t *ops);


extern int pipe_create(int type, int *id, unsigned open);


extern int pipe_init(void);


extern int pipe_free(object_t *o);


extern int pipe_avail(object_t *o);


extern int pty_init(void);


extern int special_init(void);


extern int event_init(void);


extern int tmpfile_init(void);


#endif
