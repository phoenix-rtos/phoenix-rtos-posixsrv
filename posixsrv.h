#ifndef _POSIXSRV_POSIXSRV_H_
#define _POSIXSRV_POSIXSRV_H_


typedef struct _file_ops_t file_ops_t;


typedef struct {
	unsigned refs;
	off_t offset;
	handle_t lock;
	mode_t mode;
	unsigned status;
	file_ops_t *ops;

	union {
		oid_t oid;
		void *data;
	};
} file_t;


typedef struct {
	file_t *file;
	unsigned flags;
} fildes_t;


typedef struct {
	rbnode_t linkage;

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
	ssize_t (*read)(open_file_t *, void *, size_t, unsigned);
	ssize_t (*write)(open_file_t *, void *, size_t, unsigned);
	offs_t (*lseek)(open_file_t *, offs_t, int);
};


#endif
