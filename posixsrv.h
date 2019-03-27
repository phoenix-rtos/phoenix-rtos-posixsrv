#ifndef _POSIXSRV_POSIXSRV_H_
#define _POSIXSRV_POSIXSRV_H_


#define POSIXSRV_MAX_PID ((1LL << 30) - 1)


typedef struct _file_ops_t file_ops_t;


typedef struct {
	unsigned refs;
	off_t offset;
	handle_t lock;
	mode_t mode;
	unsigned status;
	file_ops_t *ops;
	oid_t oid;
	void *data;
} file_t;


typedef struct {
	file_t *file;
	unsigned flags;
} fildes_t;


typedef struct {
	idnode_t linkage;
	handle_t lock;
	unsigned refs;

	pid_t pid;
	pid_t ppid;
	pid_t pgid;
	pid_t sid;
	uid_t uid;
	uid_t euid;
	gid_t gid;
	gid_t egid;

	unsigned fdcount;
	fildes_t *fds;
} process_t;


struct _file_ops_t {
	int (*open)(file_t *);
	int (*close)(file_t *);
	int (*read)(file_t *, ssize_t *, void *, size_t);
	int (*write)(file_t *, ssize_t *, void *, size_t);
};


typedef struct {
	handle_t lock;
	handle_t full;
	handle_t empty;
	unsigned priority;

	unsigned short max;
	unsigned short min;
	unsigned short free;
	unsigned short count;

	unsigned port;
	unsigned *rid;
	msg_t *msg;
} pool_t;



#endif
