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


enum {
	rq_timeoutIdle = 0, /* no timeout armed - the subsystem owns the request */
	rq_timeoutArmed,    /* linked in the timeout tree, still cancellable */
	rq_timeoutFired     /* claimed by the timeout thread, which will complete it */
};


typedef struct request_t {
	struct request_t *next, *prev;
	rbnode_t linkage;
	unsigned port;

	struct _object_t *object;
	time_t wakeup;
	int timeoutState;
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
				*create, *destroy, *setattr, *getattr, *getattrall,
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
	return (r->msg.type == mtWrite) ? (void *)r->msg.i.data : r->msg.o.data;
}


void rq_wakeup(request_t *r);


void rq_setResponse(request_t *r, int retval);


/* timeout expires `usecs` from now */
void rq_timeout(request_t *r, time_t usecs);


/*
 * Timeout expires at the absolute `deadline`, expressed on the raw clock that
 * gettime(&t, NULL) returns. A caller holding a CLOCK_REALTIME deadline must
 * subtract the offset reported by gettime(&raw, &offs).
 */
void rq_timeoutAt(request_t *r, time_t deadline);


int rq_timeoutCancel(request_t *r);


int rq_id(request_t *r);


unsigned posixsrv_port(void);


int posixsrv_object_link(object_t *o, const char *path);


static inline int posixsrv_object_id(object_t *o)
{
	return o->linkage.id;
}


void posixsrv_object_destroy(object_t *o);


object_t *posixsrv_object_get(int id);


void posixsrv_object_ref(object_t *o);


void posixsrv_object_put(object_t *o);


int posixsrv_object_create(object_t *o, const operations_t *ops);


int pipe_create(int type, int *id, unsigned open);


int pipe_init(void);


int pipe_free(object_t *o);


int pipe_avail(object_t *o);


int pty_init(void);


int special_init(void);


int event_init(unsigned *port);


int tmpfile_init(void);


int semaphore_init(void);


#endif
