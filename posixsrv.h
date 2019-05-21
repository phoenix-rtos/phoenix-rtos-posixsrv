#ifndef _POSIXSRV_POSIXSRV_H_
#define _POSIXSRV_POSIXSRV_H_


#define POSIXSRV_MAX_PID ((1LL << 30) - 1)
#define POSIXSRV_MAX_FDS 128

typedef struct _file_ops_t file_ops_t;


typedef struct {
	idnode_t linkage;
	const file_ops_t *ops;
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
	struct _process_t *next;
	struct _process_t *prev;

	int npid;
	rbnode_t native;

	pid_t ppid;
	pid_t pgid;
	pid_t sid;
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


struct _file_ops_t {
	int (*open)(file_t *);
	int (*close)(file_t *);
	int (*read)(file_t *, ssize_t *, void *, size_t);
	int (*write)(file_t *, ssize_t *, void *, size_t);
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


#endif
