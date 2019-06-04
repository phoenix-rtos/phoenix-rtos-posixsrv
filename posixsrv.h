#ifndef _POSIXSRV_POSIXSRV_H_
#define _POSIXSRV_POSIXSRV_H_

#include <sys/msg.h>
#include <sys/rb.h>
#include <sys/types.h>

#include "posix/idtree.h"

#define POSIXSRV_MAX_PID ((1LL << 30) - 1)
#define POSIXSRV_MAX_FDS 128

typedef struct _file_ops_t file_ops_t;


typedef struct _node_t {
	idnode_t linkage;
	const file_ops_t *ops;
	unsigned refs;

	void (*destroy)(struct _node_t *);
} node_t;


typedef struct {
	unsigned refs;
	off_t offset;
	handle_t lock;
	mode_t mode;
	unsigned status;
	const file_ops_t *ops;
	oid_t oid;
	node_t *node;
} file_t;


typedef struct {
	file_t *file;
	unsigned flags;
} fildes_t;


typedef struct _request_t {
	struct _request_t *next, *prev;

	msg_t msg;
	unsigned rid;

	struct _process_t *process;
	int (*cont)(struct _request_t *r);
	void *data;
} request_t;


typedef struct _process_t {
	idnode_t linkage;
	handle_t lock;
	unsigned refs;

	struct _process_t *children;
	struct _process_t *zombies;
	struct _process_t *next, *prev;

	struct _process_group_t *group;
	struct _process_t *pg_next, *pg_prev;

	int npid;
	rbnode_t native;

	pid_t ppid;
	uid_t uid;
	uid_t euid;
	gid_t gid;
	gid_t egid;

	oid_t cwd;

	unsigned fdcount;
	fildes_t *fds;

	struct _process_t *vfork_parent;
	int exit;

	request_t *waitpid;
} process_t;


typedef struct _process_group_t {
	pid_t id;
	process_t *members;

	struct _session_t *session;
	struct _process_group_t *next, *prev;
} process_group_t;


typedef struct _session_t {
	pid_t id;
	file_t *ctty;
	process_group_t *members;
} session_t;


struct _file_ops_t {
	int (*open)(request_t *, file_t *);
	int (*read)(request_t *, file_t *, ssize_t *, void *, size_t);
	int (*write)(request_t *, file_t *, ssize_t *, void *, size_t);
	int (*close)(file_t *);
	int (*truncate)(file_t *, int *, off_t);
	int (*ioctl)(file_t *, pid_t, unsigned, const void *, const void **);
};


typedef struct {
	handle_t lock;
	handle_t cond;
	unsigned priority;

	unsigned short max;
	unsigned short min;
	unsigned short free;
	unsigned short count;

	unsigned port;
	request_t *requests;
} pool_t;


typedef request_t *queue_t;

void request_queue_init(queue_t *q);
int request_queue_retry(request_t *r, file_t *f, queue_t *q);
int request_queue_retry_timeout(request_t *r, file_t *f, queue_t *q, int timeout_ms);
void request_continue(queue_t *q);

int fs_lookup(const char *path, oid_t *node);
int fs_create_special(oid_t dir, const char *name, int id, mode_t mode);
int msg_unlink(oid_t dir, const char *name);
int node_add(node_t *node);
void node_put(node_t *node);


#endif
