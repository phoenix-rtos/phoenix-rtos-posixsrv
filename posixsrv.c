/*
 * Phoenix-RTOS
 *
 * POSIX-compatibility module
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <sys/msg.h>
#include <sys/rb.h>
#include <sys/threads.h>
#include <sys/types.h>
#include <sys/list.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "posix/idtree.h"
#include "interface.h"
#include "posixsrv.h"

#define POSIX_RET(val, err) return (*retval = (val), (err ? printf("%s:%d err: %d\n", __func__, __LINE__, err), err : err))
#define SYSCALL_RET(val) return (((val) < 0) ? (*retval = -1), -(val) : (*retval = (val)), EOK)

#define EBLOCK (-1)

#define GET_REF(ref) __atomic_add_fetch(ref, 1, __ATOMIC_RELAXED)
#define PUT_REF(ref) __atomic_add_fetch(ref, -1, __ATOMIC_ACQ_REL)


enum { resOk, resBlock, resInvalid };


extern int pipe_create(node_t **node);
extern int pty_init(void);


static void file_ref(file_t *f);
static void posixsrv_postRequest(pool_t *pool, request_t *r);
static int posixsrv_handleRequest(request_t *r);
static int pg_new(process_t *p);
static int ses_new(process_t *p);
static void pg_remove(process_t *p);
static void pg_add(process_group_t *pg, process_t *p);


struct {
	unsigned port;
	pid_t nextpid;

	process_t *init;

	handle_t plock;
	idtree_t processes;
	rbtree_t natives;

	handle_t nlock;
	idtree_t nodes;

	node_t zero;
	node_t null;

	long long stacks[8][0x400];

	long open_files;
	long process_count;

	pool_t pool;
} posixsrv_common;


/* Utility functions */

static void splitname(char *path, char **base, char **dir)
{
	char *slash;

	slash = strrchr(path, '/');

	if (slash == NULL) {
		*dir = ".";
		*base = path;
	}
	else if (slash == path) {
		*base = path + 1;
		*dir = "/";
	}
	else {
		*dir = path;
		*base = slash + 1;
		*slash = 0;
	}
}


int fs_lookup(const char *path, oid_t *node)
{
	return -lookup(path, node, NULL);
}


static int msg_create(oid_t oid, oid_t dir, const char *name, int type, mode_t mode)
{
	int err;
	msg_t msg = {0};

	msg.type = mtCreate;
	msg.i.create.dir = dir;
	msg.i.create.dev = oid;
	msg.i.create.type = type;
	msg.i.create.mode = mode;

	msg.i.size = strlen(name) + 1;
	msg.i.data = name;

	if ((err = msgSend(dir.port, &msg)) < 0)
		return -err;

	return -msg.o.create.err;
}


int msg_link(oid_t oid, oid_t dir, const char *name)
{
	msg_t msg = {0};

	msg.type = mtLink;
	msg.i.ln.dir = dir;
	msg.i.ln.oid = oid;

	msg.i.size = strlen(name) + 1;
	msg.i.data = name;

	return -msgSend(dir.port, &msg);
}


int msg_unlink(oid_t dir, const char *name)
{
	msg_t msg = {0};

	msg.type = mtUnlink;
	msg.i.ln.dir = dir;

	msg.i.size = strlen(name) + 1;
	msg.i.data = name;

	return -msgSend(dir.port, &msg);
}


static int msg_getattr(oid_t oid, int type, int *val)
{
	int err;
	msg_t msg = {0};

	msg.type = mtGetAttr;
	msg.i.attr.oid = oid;
	msg.i.attr.type = type;

	if ((err = msgSend(oid.port, &msg)) < 0)
		return err;

	*val = msg.o.attr.val;
	return EOK;
}


static size_t fs_size(file_t *file)
{
	size_t size;

	/* TODO: handle */
	if (msg_getattr(file->oid, atSize, &size) < 0)
		return 0;

	return size;
}


int fs_create_special(oid_t dir, const char *name, int id, mode_t mode)
{
	oid_t oid;

	oid.port = posixsrv_common.port;
	oid.id = id;

	return msg_create(oid, dir, name, 0, mode);
}


/* Process functions */

static void proctree_lock(void)
{
	while (mutexLock(posixsrv_common.plock) < 0) ;
}


static void proctree_unlock(void)
{
	mutexUnlock(posixsrv_common.plock);
}


static pid_t process_pid(process_t *p)
{
	return p->linkage.id;
}


static void process_lock(process_t *p)
{
	while (mutexLock(p->lock) < 0) ;
}


static void process_unlock(process_t *p)
{
	mutexUnlock(p->lock);
}


static process_t *process_new(process_t *parent)
{
	process_t *p;
	int fd;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return NULL;

	p->refs = 1;
	p->vfork_parent = NULL;

	if (parent != NULL) {
		p->ppid = process_pid(parent);

		p->group = parent->group;
		p->uid = parent->uid;
		p->euid = parent->euid;
		p->gid = parent->gid;
		p->egid = parent->egid;

		p->cwd = parent->cwd;

		p->fdcount = parent->fdcount;
		if ((p->fds = malloc(parent->fdcount * sizeof(fildes_t))) == NULL) {
			free(p);
			return NULL;
		}

		memcpy(p->fds, parent->fds, p->fdcount * sizeof(fildes_t));

		for (fd = 0; fd < p->fdcount; ++fd) {
			if (p->fds[fd].file != NULL)
				file_ref(p->fds[fd].file);
		}

		p->refs++;
		LIST_ADD(&parent->children, p);
	}
	else {
		if (pg_new(p) != EOK || ses_new(p) != EOK) {
			free(p);
			return NULL;
		}

		p->fdcount = 16;

		if ((p->fds = calloc(p->fdcount, sizeof(fildes_t))) == NULL) {
			free(p);
			return NULL;
		}
	}

	mutexCreate(&p->lock);

	GET_REF(&posixsrv_common.process_count);

	proctree_lock();
	if (parent != NULL)
		pg_add(parent->group, p);

	p->linkage.id = posixsrv_common.nextpid++;
	idtree_alloc(&posixsrv_common.processes, &p->linkage);
	// if ((posixsrv_common.nextpid = p->pid + 1) > POSIXSRV_MAX_PID)
	//	posixsrv_common.nextpid = 1;

	proctree_unlock();

	return p;
}


static void process_destroy(process_t *p)
{
	proctree_lock();
	idtree_remove(&posixsrv_common.processes, &p->linkage);
	proctree_unlock();

	free(p);
	PUT_REF(&posixsrv_common.process_count);
}


static process_t *process_find(pid_t pid)
{
	process_t *p;

	proctree_lock();
	if ((p = lib_treeof(process_t, linkage, idtree_find(&posixsrv_common.processes, pid))) != NULL)
		GET_REF(&p->refs);
	proctree_unlock();

	return p;
}


static process_t *process_nativeFind(int npid)
{
	process_t *p, t;

	t.npid = npid;

	proctree_lock();
	if ((p = lib_treeof(process_t, native, lib_rbFind(&posixsrv_common.natives, &t.native))) != NULL)
		GET_REF(&p->refs);
	proctree_unlock();

	return p;
}


static void process_put(process_t *p)
{
	if (p && !PUT_REF(&p->refs))
		process_destroy(p);
}


static void process_ref(process_t *p)
{
	if (p)
		GET_REF(&p->refs);
}



/* Session functions */

static void ses_destroy(session_t *ses)
{
	free(ses);
}


static int ses_leader(process_t *p)
{
	return process_pid(p) == p->group->session->id;
}


static void ses_add(session_t *ses, process_group_t *pg)
{
	pg->session = ses;
	LIST_ADD(&ses->members, pg);
}


static void ses_remove(process_group_t *pg)
{
	session_t *ses = pg->session;

	if (ses != NULL) {
		LIST_REMOVE(&ses->members, pg);

		if (ses->members == NULL)
			ses_destroy(ses);

		pg->session = NULL;
	}
}


static int ses_new(process_t *p)
{
	session_t *ses;

	if ((ses = calloc(1, sizeof(*ses))) == NULL)
		return ENOMEM;

	ses->id = process_pid(p);
	ses_remove(p->group);
	ses_add(ses, p->group);

	return EOK;
}



/* Process group functions */

static void pg_destroy(process_group_t *pg)
{
	free(pg);
}


static int pg_leader(process_t *p)
{
	return process_pid(p) == p->group->id;
}


static void pg_add(process_group_t *pg, process_t *p)
{
	p->group = pg;
	LIST_ADD_EX(&pg->members, p, pg_next, pg_prev);
}


static void pg_remove(process_t *p)
{
	process_group_t *pg = p->group;

	if (pg) {
		LIST_REMOVE_EX(&pg->members, p, pg_next, pg_prev);

		if (pg->members == NULL) {
			ses_remove(pg);
			pg_destroy(pg);
		}

		p->group = NULL;
	}
}


static int pg_new(process_t *p)
{
	process_group_t *pg;

	if ((pg = calloc(1, sizeof(*pg))) == NULL)
		return ENOMEM;

	pg->id = process_pid(p);

	if (p->group)
		ses_add(p->group->session, pg);

	pg_remove(p);
	pg_add(pg, p);

	return EOK;
}


/* Generic operations for files */

static int generic_open(request_t *request, file_t *file)
{
	msg_t msg;

	msg.i.data = msg.o.data = NULL;
	msg.i.size = msg.o.size = 0;

	msg.type = mtOpen;
	msg.i.openclose.oid = file->oid;
	msg.i.openclose.flags = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err < 0)
		return -msg.o.io.err;

	return EOK;
}


static int generic_close(file_t *file)
{
	msg_t msg;

	msg.i.data = msg.o.data = NULL;
	msg.i.size = msg.o.size = 0;

	msg.type = mtClose;
	msg.i.openclose.oid = file->oid;
	msg.i.openclose.flags = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	if (msg.o.io.err < 0)
		return -msg.o.io.err;

	return EOK;
}


static int generic_write(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	msg_t msg;

	msg.i.data = data;
	msg.i.size = size;

	msg.o.data = NULL;
	msg.o.size = 0;

	msg.type = mtWrite;
	msg.i.io.oid = file->oid;
	msg.i.io.offs = file->offset;
	msg.i.io.mode = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	SYSCALL_RET(msg.o.io.err);
}


static int generic_read(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	msg_t msg;

	msg.i.data = NULL;
	msg.i.size = 0;

	msg.o.data = data;
	msg.o.size = size;

	msg.type = mtRead;
	msg.i.io.oid = file->oid;
	msg.i.io.offs = file->offset;
	msg.i.io.mode = 0; /* FIXME: field not necessary? */

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	SYSCALL_RET(msg.o.io.err);
}


static int generic_truncate(file_t *file, int *retval, off_t length)
{
	msg_t msg;

	msg.i.data = NULL;
	msg.i.size = 0;

	msg.o.data = NULL;
	msg.o.size = 0;

	msg.type = mtTruncate;
	msg.i.io.oid = file->oid;
	msg.i.io.len = length;

	if (msgSend(file->oid.port, &msg) < 0)
		return EIO;

	/* FIXME: agree on sign convention and meaning? */
	SYSCALL_RET(msg.o.io.err);
}


const static file_ops_t generic_ops = {
	.open = generic_open,
	.close = generic_close,
	.read = generic_read,
	.write = generic_write,
	.truncate = generic_truncate,
};


/* File functions */

static void file_lock(file_t *f)
{
	while (mutexLock(f->lock) < 0) ;
}


static void file_unlock(file_t *f)
{
	mutexUnlock(f->lock);
}


static void file_destroy(file_t *f)
{
	if (f->ops != NULL)
		f->ops->close(f);

	if (f->node != NULL)
		node_put(f->node);

	resourceDestroy(f->lock);
	free(f);

	PUT_REF(&posixsrv_common.open_files);
}


static void file_ref(file_t *f)
{
	GET_REF(&f->refs);
}


static void file_deref(file_t *f)
{
	if (f && !PUT_REF(&f->refs))
		file_destroy(f);
}


/* File descriptor table functions */

static int _fd_realloc(process_t *p)
{
	fildes_t *new;
	int fdcount;

	fdcount = p->fdcount * 2;

	if ((new = realloc(p->fds, fdcount * sizeof(fildes_t))) == NULL)
		return ENOMEM;

	memset(new + p->fdcount, 0, p->fdcount * sizeof(fildes_t));
	p->fds = new;
	p->fdcount = fdcount;

	return EOK;
}


static int _fd_alloc(process_t *p, int fd)
{
	if (fd < 0)
		fd = 0;

	while (fd < p->fdcount) {
		if (p->fds[fd].file == NULL)
			return fd;

		fd++;
	}

	return -1;
}


static int _file_new(process_t *p, int *fd, file_t **file)
{
	file_t *f;
	int newfd;

	if ((newfd = _fd_alloc(p, *fd)) < 0) {
		newfd = p->fdcount;

		/* TODO: set a limit for fd's */
		if (_fd_realloc(p) != EOK)
			return ENOMEM;

		newfd = _fd_alloc(p, newfd);
	}

	*fd = newfd;

	if ((*file = f = p->fds[*fd].file = malloc(sizeof(file_t))) == NULL)
		return ENOMEM;

	memset(f, 0, sizeof(file_t));
	mutexCreate(&f->lock);
	f->refs = 2;
	f->offset = 0;
	f->mode = 0;
	f->status = 0;
	f->ops = NULL;

	GET_REF(&posixsrv_common.open_files);

	return EOK;
}


static file_t *_file_get(process_t *p, int fd)
{
	file_t *f;

	if (fd < 0 || fd >= p->fdcount || (f = p->fds[fd].file) == NULL || f->ops == NULL)
		return NULL;

	file_ref(f);
	return f;
}


static int _file_close(process_t *p, int fd)
{
	if (fd < 0 || fd >= p->fdcount || p->fds[fd].file == NULL)
		return EBADF;

	file_deref(p->fds[fd].file);
	p->fds[fd].file = NULL;
	return EOK;
}


static int file_new(process_t *p, int *fd, file_t **file)
{
	int err_no;
	process_lock(p);
	err_no = _file_new(p, fd, file);
	process_unlock(p);
	return err_no;
}


static file_t *file_get(process_t *p, int fd)
{
	file_t *f;
	process_lock(p);
	f = _file_get(p, fd);
	process_unlock(p);
	return f;
}


static int file_close(process_t *p, int fd)
{
	int err_no;
	process_lock(p);
	err_no = _file_close(p, fd);
	process_unlock(p);
	return err_no;
}


/* Internal files */

static void nodetree_lock(void)
{
	while (mutexLock(posixsrv_common.nlock) < 0) ;
}


static void nodetree_unlock(void)
{
	mutexUnlock(posixsrv_common.nlock);
}


static void node_destroy(node_t *node)
{
	nodetree_lock();
	idtree_remove(&posixsrv_common.nodes, &node->linkage);
	nodetree_unlock();

	node->destroy(node);
}


static void node_ref(node_t *node)
{
	GET_REF(&node->refs);
}


void node_put(node_t *node)
{
	if (node && !PUT_REF(&node->refs))
		node_destroy(node);
}


static void node_deref(oid_t *oid)
{
	node_t *node;

	if (oid->port != posixsrv_common.port)
		return;

	nodetree_lock();
	if ((node = lib_treeof(node_t, linkage, idtree_find(&posixsrv_common.nodes, oid->id))) != NULL) {
		if (!PUT_REF(&node->refs)) {
			idtree_remove(&posixsrv_common.nodes, &node->linkage);
			node->destroy(node);
		}
	}
	nodetree_unlock();
}


static node_t *node_get(oid_t *oid)
{
	node_t *node;

	if (oid->port != posixsrv_common.port)
		return NULL;

	nodetree_lock();
	if ((node = lib_treeof(node_t, linkage, idtree_find(&posixsrv_common.nodes, oid->id))) != NULL)
		node_ref(node);
	nodetree_unlock();

	return node;
}


int node_add(node_t *node)
{
	int id;

	nodetree_lock();
	id = idtree_alloc(&posixsrv_common.nodes, &node->linkage);
	nodetree_unlock();

	return id;
}


/* /dev/zero */

static int zero_open(request_t *request, file_t *file)
{
	return EOK;
}


static int zero_close(file_t *file)
{
	return EOK;
}


static int zero_write(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(size, EOK);
}


static int zero_read(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	memset(data, 0, size);
	POSIX_RET(size, EOK);
}


static const file_ops_t zero_ops = {
	.open = zero_open,
	.close = zero_close,
	.read = zero_read,
	.write = zero_write
};


/* /dev/null */

static int null_open(request_t *request, file_t *file)
{
	return EOK;
}


static int null_close(file_t *file)
{
	return EOK;
}


static int null_write(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(size, EOK);
}


static int null_read(request_t *request, file_t *file, ssize_t *retval, void *data, size_t size)
{
	POSIX_RET(0, EOK);
}


static const file_ops_t null_ops = {
	.open = null_open,
	.close = null_close,
	.read = null_read,
	.write = null_write
};


/* /dev/ptmx */
#if 0
static int ptmx_open(file_t *file)
{
	if ((file->node = pty_new()) == NULL)
		return ENOMEM;

	return EOK;
}
#endif

/* File operation wrappers */


static int posix_write(request_t *r, int fd, void *buf, size_t nbyte, ssize_t *retval)
{
	int err_no;
	file_t *f;

	if ((f = file_get(r->process, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	err_no = f->ops->write(r, f, retval, buf, nbyte);
	file_deref(f);
	return err_no;
}


static int posix_read(request_t *r, int fd, void *buf, size_t nbyte, ssize_t *retval)
{
	file_t *f;
	int err_no;

	if ((f = file_get(r->process, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	err_no = f->ops->read(r, f, retval, buf, nbyte);
	file_deref(f);
	return err_no;
}


static int posix_open(request_t *r, char *path, int oflag, mode_t mode, int *retval)
{
	oid_t oid;
	int err_no, fd = 0;
	file_t *file;

	/* TODO: canonicalize path */
	if (lookup(path, NULL, &oid) < 0)
		POSIX_RET(-1, ENOENT);

	if ((err_no = file_new(r->process, &fd, &file)))
		POSIX_RET(-1, err_no);

	file_lock(file);
	if ((file->node = node_get(&oid)) != NULL)
		file->ops = file->node->ops;
	else
		file->ops = &generic_ops;

	file->oid = oid;

	if ((err_no = file->ops->open(r, file))) {
		file_close(r->process, fd);
		fd = -1;
	}
	file_unlock(file);

	file_deref(file);
	POSIX_RET(fd, err_no);
}


static int posix_close(process_t *p, int fd, int *retval)
{
	int err_no;

	if ((err_no = file_close(p, fd)))
		POSIX_RET(-1, err_no);

	POSIX_RET(0, EOK);
}


/* Other calls */

static int _posix_dup(process_t *p, int fd, int *retval)
{
	int newfd;
	file_t *f;

	if (fd < 0 || fd >= p->fdcount)
		POSIX_RET(-1, EBADF);

	if ((newfd = _fd_alloc(p, 0)) < 0)
		POSIX_RET(-1, EMFILE);

	if ((f = _file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	p->fds[newfd].file = f;
	p->fds[newfd].flags = 0;

	POSIX_RET(newfd, EOK);
}


static int posix_dup(process_t *p, int fd, int *retval)
{
	int err_no;

	process_lock(p);
	err_no = _posix_dup(p, fd, retval);
	process_unlock(p);
	return err_no;
}


static int _posix_dup2(process_t *p, int fd, int fd2, int *retval)
{
	file_t *f, *f2;

	if (fd == fd2)
		POSIX_RET(fd, EOK);

	if (fd2 < 0 || fd2 >= p->fdcount)
		POSIX_RET(-1, EBADF);

	if ((f = _file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	if ((f2 = p->fds[fd2].file) != NULL)
		file_deref(f2);

	p->fds[fd2].file = f;
	p->fds[fd2].flags = 0;

	POSIX_RET(fd2, EOK);
}


static int posix_dup2(process_t *p, int fd1, int fd2, int *retval)
{
	int err_no;

	process_lock(p);
	err_no = _posix_dup2(p, fd1, fd2, retval);
	process_unlock(p);
	return err_no;
}


static int posix_pipe(process_t *p, int fd[2], int *retval)
{
	int err_no;
	file_t *pipe = NULL;
	node_t *node;

	fd[0] = fd[1] = -1;

	if ((err_no = file_new(p, fd, &pipe)))
		goto err;

	if ((err_no = pipe_create(&node)))
		goto err;

	file_lock(pipe);
	pipe->node = node;
	pipe->ops = node->ops;
	pipe->status = O_RDWR;
	file_unlock(pipe);

	if ((err_no = posix_dup(p, fd[0], &fd[1])))
		goto err;

	file_deref(pipe);
	POSIX_RET(0, EOK);

err:
	file_close(p, fd[0]);
	file_close(p, fd[1]);

	file_deref(pipe);
	POSIX_RET(-1, err_no);
}


static int posix_mkfifo(process_t *p, const char *pathname, mode_t mode, int *retval)
{
	char *pathcopy;
	char *dirname, *basename;
	int err_no, id;
	oid_t dir;
	node_t *pipe;

	if ((pathcopy = strdup(pathname)) == NULL) {
		err_no = ENOMEM;
		goto out;
	}

	splitname(pathcopy, &basename, &dirname);

	if ((err_no = fs_lookup(dirname, &dir)))
		goto out;

	if ((err_no = pipe_create(&pipe)))
		goto out;

	id = node_add(pipe);
	err_no = fs_create_special(dir, basename, id, DEFFILEMODE | S_IFIFO);

out:
	free(pathcopy);

	if (err_no) {
		// remove
	}

	POSIX_RET(-!!err_no, err_no);
}


static int native_cmp(rbnode_t *n1, rbnode_t *n2)
{
	process_t *p1 = lib_treeof(process_t, native, n1);
	process_t *p2 = lib_treeof(process_t, native, n2);

	if (p1->npid < p2->npid)
		return -1;

	else if (p1->npid > p2->npid)
		return 1;

	return 0;
}


static void native_unlink(process_t *p)
{
	lib_rbRemove(&posixsrv_common.natives, &p->native);
}


static void native_link(process_t *p, int pid)
{
	p->npid = pid;
	lib_rbInsert(&posixsrv_common.natives, &p->native);
}


static int native_spawn(const char *path, char *const argv[], char *const envp[])
{
	extern int sys_spawn(const char *, char * const *, char * const *);
	return sys_spawn(path, argv, envp);
}


static int posix_execve(process_t *p, const char *path, char *const argv[], char *const envp[], int *retval)
{
	process_t *v;
	int npid;
	int fd;

	process_lock(p);

	for (fd = 0; fd < p->fdcount; ++fd) {
		if (p->fds[fd].file != NULL && p->fds[fd].flags & FD_CLOEXEC)
			_file_close(p, fd);
	}

	if ((v = p->vfork_parent) != NULL) {
		p->vfork_parent = NULL;
		process_lock(v);
	}

	proctree_lock();

	if ((npid = native_spawn(path, argv, envp)) > 0) {
		native_unlink(p);
		native_link(p, npid);

		if (v != NULL)
			native_link(v, v->npid);
	}

	proctree_unlock();

	if (v != NULL) {
		process_unlock(v);
		process_put(v);
	}

	process_unlock(p);

	SYSCALL_RET(npid);
}


static int posix_vfork(process_t *p, int *retval)
{
	process_t *c;

	process_lock(p);

	if ((c = process_new(p)) == NULL) {
		process_unlock(p);
		POSIX_RET(-1, ENOMEM);
	}

	process_lock(c);

	process_ref(p);
	c->vfork_parent = p;

	proctree_lock();
	native_unlink(p);
	native_link(c, p->npid);
	proctree_unlock();

	process_unlock(c);
	process_unlock(p);

	process_put(c);

	POSIX_RET(process_pid(c), EOK);
}


static void waitpid_wakeup(process_t *p)
{
	request_t *r;
	while ((r = p->waitpid) != NULL) {
		LIST_REMOVE(&p->waitpid, r);
		posixsrv_postRequest(&posixsrv_common.pool, r);
	}
}


static int posix_exit(process_t *p, int status)
{
	process_t *parent;
	int fd;
	pid_t ppid;

	process_lock(p);
	for (fd = 0; fd < p->fdcount; ++fd) {
		if (p->fds[fd].file != NULL)
			_file_close(p, fd);
	}

	ppid = p->ppid;
	p->exit = status;

	proctree_lock();
	pg_remove(p);
	proctree_unlock();
	process_unlock(p);

	if ((parent = process_find(ppid)) != NULL) {
		process_lock(parent);
		LIST_REMOVE(&parent->children, p);
		LIST_ADD(&parent->zombies, p);
		waitpid_wakeup(parent);
		process_unlock(parent);
	}

	return EOK;
}


static int waitpid_ok(pid_t pid, process_t *p, process_t *z)
{
	return pid == -1 || (!pid && z->group->id == p->group->id) || (pid < 0 && z->group->id == -pid) || pid == process_pid(z);
}


static int waitpid_reap(process_t *z)
{
	return z->exit;
}


static int posix_waitpid(process_t *p, pid_t pid, int *status, int options, pid_t *retval)
{
	int ret = 0, err = EOK;
	process_t *z, *reap = NULL;

	process_lock(p);

	if ((z = p->zombies) != NULL) {
		do {
			if (waitpid_ok(pid, p, z)) {
				reap = z;
				break;
			}
		} while ((z = z->next) != p->zombies);
	}

	if (reap != NULL) {
		ret = process_pid(reap);
		LIST_REMOVE(&p->zombies, reap);
		*status = waitpid_reap(reap);
		process_put(reap);
	}
	else if (p->children == NULL) {
		err = ECHILD;
		ret = -1;
	}
	else if (!(options & WNOHANG)) {
		err = EBLOCK;
	}

	process_unlock(p);
	POSIX_RET(ret, err);
}


static int posix_ftruncate(process_t *p, int fd, off_t length, int *retval)
{
	file_t *f;
	int err_no;

	if ((f = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	err_no = f->ops->truncate(f, retval, length);
	file_deref(f);
	return err_no;
}


static int posix_link(process_t *p, const char *path1, const char *path2, int *retval)
{
	int err;
	char *name, *basename, *dirname;
	oid_t src, dir;

	name = strdup(path2);
	splitname(name, &basename, &dirname);

	if ((err = fs_lookup(dirname, &dir)) != EOK) {
		*retval = -1;
	}
	else if ((err = fs_lookup(path1, &src)) != EOK) {
		*retval = -1;
	}
	else if ((err = msg_link(src, dir, basename)) != EOK) {
		*retval = -1;
	}
	else {
		/* Bump reference count if it's a file we manage */
		node_get(&src);
		*retval = 0;
	}

	free(name);
	return err;
}


static int posix_unlink(process_t *p, const char *path, int *retval)
{
	int err;
	char *name, *basename, *dirname;
	oid_t src, dir;

	name = strdup(path);
	splitname(name, &basename, &dirname);

	if ((err = fs_lookup(dirname, &dir)) != EOK) {
		*retval = -1;
	}
	else if ((err = fs_lookup(path, &src)) != EOK) {
		*retval = -1;
	}
	else if ((err = msg_unlink(dir, basename)) != EOK) {
		*retval = -1;
	}
	else {
		node_deref(&src);
		*retval = 0;
	}

	free(name);
	return err;
}


static int posix_setsid(process_t *p, pid_t *retval)
{
	int err = 0;

	process_lock(p);
	proctree_lock();
	if (pg_leader(p)) {
		*retval = -1;
		err = EPERM;
	}
	else if (pg_new(p) != EOK || ses_new(p) != EOK) {
		*retval = -1;
		err = ENOMEM;
	}
	else {
		*retval = p->group->session->id;
	}
	proctree_unlock();
	process_unlock(p);

	return err;
}


static int posix_setpgid(process_t *p, pid_t pid, pid_t pgid, int *retval)
{
	process_t *s;
	process_group_t *pg;
	int err;

	if (pgid < 0) {
		*retval = -1;
		return EINVAL;
	}

	process_lock(p);
	if (!pid) {
		pid = process_pid(p);
		s = p;
	}
	else if ((s = p->children) != NULL) {
		do {
			if (process_pid(s) == pid)
				break;
		} while ((s = s->next) != p->children);
	}

	if (!s || process_pid(s) != pid) {
		process_unlock(p);
		*retval = -1;
		return ESRCH;
	}

	proctree_lock();
	if (ses_leader(s) || s->group->session != p->group->session) {
		*retval = -1;
		err = EPERM;
	}
	else if (pgid == 0) {
		pg_new(s);

		*retval = 0;
		err = EOK;
	}
	else {
		pg = s->group;
		do {
			if (pg->id == pgid)
				break;
		} while ((pg = pg->next) != s->group);

		if (pg->id == pgid) {
			pg_remove(s);
			pg_add(pg, s);

			*retval = 0;
			err = EOK;
		}
		else {
			*retval = -1;
			err = EPERM;
		}
	}
	proctree_unlock();
	process_unlock(p);

	return err;
}


static int posix_getpgid(process_t *p, pid_t pid, pid_t *retval)
{
	process_t *s;
	int err;

	if (pid < 0) {
		*retval = -1;
		return EINVAL;
	}

	if (pid != 0)
		s = process_find(pid);
	else
		s = p;

	if (s == NULL) {
		*retval = -1;
		return ESRCH;
	}

	proctree_lock();
	if (s->group->session->id != p->group->session->id) {
		/* NOTE: disallowing this is optional */
		*retval = -1;
		err = EPERM;
	}
	else {
		*retval = s->group->id;
		err = EOK;
	}
	proctree_unlock();

	if (pid != 0)
		process_put(s);

	return err;
}


static int posix_getsid(process_t *p, pid_t pid, pid_t *retval)
{
	process_t *s;
	int err;

	if (pid < 0) {
		*retval = -1;
		return EINVAL;
	}

	if (pid != 0)
		s = process_find(pid);
	else
		s = p;

	if (s == NULL) {
		*retval = -1;
		return ESRCH;
	}

	proctree_lock();
	if (s->group->session->id != p->group->session->id) {
		/* NOTE: disallowing this is optional */
		*retval = -1;
		err = EPERM;
	}
	else {
		*retval = s->group->session->id;
		err = EOK;
	}
	proctree_unlock();

	if (pid != 0)
		process_put(s);

	return err;
}


static int posix_getppid(process_t *p, pid_t *retval)
{
	process_lock(p);
	*retval = p->ppid;
	process_unlock(p);

	return EOK;
}


static int posix_lseek(process_t *p, int fd, off_t offset, int whence, off_t *retval)
{
	file_t *file;
	off_t result;
	int err = EOK;
	size_t size;

	if ((file = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	if (S_ISFIFO(file->mode)) {
		file_deref(file);
		POSIX_RET(-1, ESPIPE);
	}

	file_lock(file);
	switch (whence) {
	case SEEK_SET:
		file->offset = offset;
		result = offset;
		break;

	case SEEK_CUR:
		file->offset -= offset;
		result = file->offset;
		break;

	case SEEK_END:
		/* TODO: use file->ops to getattr size? */
		size = fs_size(file);
		file->offset = size - offset;
		result = file->offset;
		break;

	default:
		err = EINVAL;
		result = -1;
	}
	file_unlock(file);
	file_deref(file);

	POSIX_RET(result, err);
}


int posix_fstat(process_t *p, int fd, struct stat *buf, int *retval)
{
	file_t *file;
	int err;

	if ((file = file_get(p, fd)) == NULL)
		POSIX_RET(-1, EBADF);

	// err = file->ops->getattr(file, buf);

	file_deref(file);
	POSIX_RET(0, EOK);
}


static int posix_init(int pid)
{
	process_t *init;

	if (posixsrv_common.init)
		return EACCES;

	if ((init = posixsrv_common.init = process_new(NULL)) == NULL)
		return ENOMEM;

	process_lock(init);
	proctree_lock();
	native_link(init, pid);
	proctree_unlock();
	process_unlock(init);

	return EOK;
}


/* Handler functions */

/* init attaches first process to sender */
static int handle_init(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	_o->err_no = posix_init(r->msg.pid);
	return resOk;
}


static int handle_write(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd = _i->write.fd;
	void *data = r->msg.i.data;
	size_t size = r->msg.i.size;
	ssize_t *retval = &_o->write.retval;

	if ((_o->err_no = posix_write(r, fd, data, size, retval)) == EBLOCK)
		return resBlock;

	return resOk;
}


static int handle_read(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd = _i->read.fd;
	void *data = r->msg.o.data;
	size_t size = r->msg.o.size;
	ssize_t *retval = &_o->read.retval;

	if ((_o->err_no = posix_read(r, fd, data, size, retval)) == EBLOCK)
		return resBlock;

	return resOk;
}


static int handle_open(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int oflag = _i->open.oflag;
	mode_t mode = _i->open.mode;
	char *path = r->msg.i.data;
	int *retval = &_o->open.retval;

	_o->err_no = posix_open(r, path, oflag, mode, retval);
	return resOk;
}


static int handle_close(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd = _i->close.fd;
	ssize_t *retval = &_o->close.retval;

	_o->err_no = posix_close(r->process, fd, retval);
	return resOk;
}


static int handle_pipe(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int *fd = _o->pipe.fd;
	int *retval = &_o->pipe.retval;

	_o->err_no = posix_pipe(r->process, fd, retval);
	return resOk;
}


static int handle_mkfifo(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	const char *pathname = r->msg.i.data;
	mode_t mode = _i->mkfifo.mode;
	int *retval = &_o->pipe.retval;

	_o->err_no = posix_mkfifo(r->process, pathname, mode, retval);
	return resOk;
}


static int handle_dup(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd = _i->dup.fd;
	int *retval = &_o->dup.retval;

	_o->err_no = posix_dup(r->process, fd, retval);
	return resOk;
}


static int handle_dup2(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd1 = _i->dup2.fd1;
	int fd2 = _i->dup2.fd2;
	int *retval = &_o->dup2.retval;

	_o->err_no = posix_dup2(r->process, fd1, fd2, retval);
	return resOk;
}


static int handle_recvfrom(request_t *r)
{
	return resOk;
}


static int handle_execve(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;
	int *retval = &_o->execve.retval;

	size_t size = r->msg.i.size;
	char *data;
	char *path;
	char **argv;
	char **envp;

	int argc = 0;
	int envc = 0;
	int i;

	size_t len;
	char *s, *argv0;

	if ((data = malloc(size)) == NULL) {
		_o->err_no = ENOMEM;
		_o->execve.retval = -1;
		return resOk;
	}

	memcpy(data, r->msg.i.data, size);

	path = data;
	argv0 = s = path + strlen(path) + 1;

	while (s < data + size) {
		if (!(len = strlen(s)))
			break;

		argc++;
		s += len + 1;
	}

	while (s < data + size) {
		if (!(len = strlen(s)))
			break;

		envc++;
		s += len + 1;
	}

	if ((argv = malloc((argc + 1) * sizeof(char *))) == NULL) {
		free(data);

		_o->err_no = ENOMEM;
		_o->execve.retval = -1;
		return resOk;
	}

	if ((envp = malloc((envc + 1) * sizeof(char *))) == NULL) {
		free(data);
		free(argv);

		_o->err_no = ENOMEM;
		_o->execve.retval = -1;
		return resOk;
	}

	s = argv0;

	for (i = 0; i <= argc; ++i) {
		argv[i] = s;
		s += strlen(s) + 1;
	}

	argv[argc] = NULL;

	for (i = 0; i < envc; ++i) {
		envp[i] = s;
		s += strlen(s) + 1;
	}

	envp[envc] = NULL;

	_o->err_no = posix_execve(r->process, path, argv, envp, retval);

	/* data, argv & envp are consumed by posix_execve on success */
	if (_o->err_no) {
		free(data);
		free(argv);
		free(envp);
	}

	return resOk;
}


static int handle_vfork(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;
	int *retval = &_o->vfork.retval;

	_o->err_no = posix_vfork(r->process, retval);
	return resOk;
}


static int handle_exit(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;
	int status = _i->exit.status;

	_o->err_no = posix_exit(r->process, status);
	return resOk;
}


static int handle_waitpid(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t pid = _i->waitpid.pid;
	int options = _i->waitpid.options;
	int *status = &_o->waitpid.status;
	pid_t *retval = &_o->waitpid.retval;

	if ((_o->err_no = posix_waitpid(r->process, pid, status, options, retval)) == EBLOCK) {
		LIST_ADD(&r->process->waitpid, r);
		return resBlock;
	}

	return resOk;
}


static int handle_getpid(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;
	pid_t *retval = &_o->getpid.retval;

	*retval = process_pid(r->process);
	_o->err_no = EOK;

	return resOk;
}


static int handle_link(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int *retval = &_o->link.retval;
	const char *path1 = r->msg.i.data;
	const char *path2 = r->msg.i.data + strnlen(path1, r->msg.i.size - 2) + 1;

	_o->err_no = posix_link(r->process, path1, path2, retval);
	return resOk;
}


static int handle_unlink(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int *retval = &_o->link.retval;
	const char *path = r->msg.i.data;

	_o->err_no = posix_unlink(r->process, path, retval);
	return resOk;
}


static int handle_ftruncate(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int fd = _i->ftruncate.fd;
	off_t length = _i->ftruncate.length;
	int *retval = &_o->ftruncate.retval;

	_o->err_no = posix_ftruncate(r->process, fd, length, retval);
	return resOk;
}


static int handle_setsid(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t *retval = &_o->setsid.retval;

	_o->err_no = posix_setsid(r->process, retval);
	return resOk;
}


static int handle_setpgid(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t *retval = &_o->setsid.retval;
	pid_t pid = _i->setpgid.pid;
	pid_t pgid = _i->setpgid.pgid;

	_o->err_no = posix_setpgid(r->process, pid, pgid, retval);
	return resOk;
}


static int handle_getpgid(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t *retval = &_o->getpgid.retval;
	pid_t pid = _i->getpgid.pid;

	_o->err_no = posix_getpgid(r->process, pid, retval);
	return resOk;
}


static int handle_getsid(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t *retval = &_o->getsid.retval;
	pid_t pid = _i->getsid.pid;

	_o->err_no = posix_getsid(r->process, pid, retval);
	return resOk;
}


static int handle_getppid(request_t *r)
{
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	pid_t *retval = &_o->getppid.retval;

	_o->err_no = posix_getppid(r->process, retval);
	return resOk;
}


static int handle_lseek(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	off_t *retval = &_o->lseek.retval;
	int fd = _i->lseek.fd;
	off_t offset = _i->lseek.offset;
	int whence = _i->lseek.whence;

	_o->err_no = posix_lseek(r->process, fd, offset, whence, retval);
	return resOk;
}


static int handle_fstat(request_t *r)
{
	posixsrv_i_t *_i = (void *)r->msg.i.raw;
	posixsrv_o_t *_o = (void *)r->msg.o.raw;

	int *retval = &_o->fstat.retval;
	int fd = _i->fstat.fd;
	struct stat *buf = r->msg.o.data;

	_o->err_no = posix_fstat(r->process, fd, buf, retval);
	return resOk;
}



/* */

void request_queue_init(queue_t *q)
{
	*q = NULL;
}


int request_queue_retry(request_t *r, file_t *f, queue_t *q)
{
	int err;

	file_lock(f);
	if (f->status & O_NONBLOCK) {
		err = EWOULDBLOCK;
	}
	else {
		LIST_ADD(q, r);
		err = EBLOCK;
	}
	file_unlock(f);

	return err;
}


int request_queue_retry_timeout(request_t *r, file_t *f, queue_t *q, int timeout_ms)
{
	/* TODO */
	return request_queue_retry(r, f, q);
}


void request_continue(queue_t *q)
{
	request_t *r;

	while ((r = *q) != NULL) {
		LIST_REMOVE(q, r);
		posixsrv_postRequest(&posixsrv_common.pool, r);
	}
}


/* Interface threads */

static int posixsrv_handleRequest(request_t *r)
{
	int err;

#define POSIXSRV_CASE(name) \
	case posixsrv_##name: err = r->process != NULL ? handle_##name(r) : resInvalid; break;

	switch (r->msg.type) {
		case posixsrv_init:
			err = handle_init(r);
			break;

		POSIXSRV_CALLS(POSIXSRV_CASE)
		default:
			err = resInvalid;
			break;
	}
#undef POSIXSRV_CASE

	return err;
}


/* Threadpool functions */

static void pool_lock(pool_t *pool)
{
	while (mutexLock(pool->lock) < 0) ;
}


static void pool_unlock(pool_t *pool)
{
	mutexUnlock(pool->lock);
}


static void pool_waitEmpty(pool_t *pool)
{
	condWait(pool->cond, pool->lock, 0);
}


static request_t *posixsrv_newRequest(pool_t *pool)
{
	request_t *r;

	if ((r = malloc(sizeof(*r))) != NULL) {
		r->cont = posixsrv_handleRequest;
		r->process = NULL;
		r->data = NULL;
	}

	return r;
}


static void posixsrv_freeRequest(pool_t *pool, request_t *r)
{
	process_put(r->process);
	free(r);
}


static void posixsrv_postRequest(pool_t *pool, request_t *r)
{
	pool_lock(pool);
	LIST_ADD(&pool->requests, r);
	pool_unlock(pool);
	condSignal(pool->cond);
}


static request_t *posixsrv_getRequest(pool_t *pool)
{
	request_t *r;
	pool_lock(pool);
	while ((r = pool->requests) == NULL)
		pool_waitEmpty(pool);

	LIST_REMOVE(&pool->requests, r);
	pool_unlock(pool);

	if (r->process == NULL)
		r->process = process_nativeFind(r->msg.pid);

	return r;
}


static void posixsrv_poolThread(void *arg)
{
	pool_t *pool = arg;
	request_t *r;
	int res;

	pool_lock(pool);
	pool->count++;
	pool_unlock(pool);

	for (;;) {
		r = posixsrv_getRequest(pool);

		priority(r->msg.priority);
		res = r->cont(r);

		switch (res) {
			case resInvalid:
				kill(r->msg.pid, SIGSYS);

				/* fallthrough */
			case resOk:
				msgRespond(pool->port, &r->msg, r->rid);
				posixsrv_freeRequest(pool, r);
				break;

			case resBlock:
				break;
		}

		priority(pool->priority);
	}
}


static void posixsrv_msgThread(void *arg)
{
	pool_t *pool = arg;
	request_t *r;
	int err;

	for (;;) {
		while ((r = posixsrv_newRequest(pool)) == NULL)
			usleep(100000);

		while ((err = msgRecv(pool->port, &r->msg, &r->rid)) < 0) {
			if (err != -EINTR)
				usleep(50000);

			continue;
		}

		posixsrv_postRequest(pool, r);
	}
}


static void init(void)
{
	portCreate(&posixsrv_common.port);
	portRegister(posixsrv_common.port, "/posixsrv", NULL);
	idtree_init(&posixsrv_common.processes);
	lib_rbInit(&posixsrv_common.natives, native_cmp, NULL);
	mutexCreate(&posixsrv_common.plock);
	mutexCreate(&posixsrv_common.nlock);
	posixsrv_common.nextpid = 1;
}


static void pool_init(pool_t *pool, unsigned port)
{
	mutexCreate(&pool->lock);
	condCreate(&pool->cond);
	pool->priority = 1;
	pool->max = pool->min = sizeof(posixsrv_common.stacks) / sizeof(posixsrv_common.stacks[0]);
	pool->free = 0;
	pool->count = 0;
	pool->port = port;
	pool->requests = NULL;
}


static void special_init(void)
{
	idtree_init(&posixsrv_common.nodes);

	posixsrv_common.zero.ops = &zero_ops;
	node_add(&posixsrv_common.zero);

	posixsrv_common.null.ops = &null_ops;
	node_add(&posixsrv_common.null);
}


int main(int argc, char **argv)
{
	int i;
	pool_t *pool = &posixsrv_common.pool;

	init();
	special_init();
	pool_init(pool, posixsrv_common.port);
	pty_init();

	for (i = 0; i < pool->min; ++i)
		beginthread(posixsrv_poolThread, pool->priority, posixsrv_common.stacks[i], sizeof(posixsrv_common.stacks[i]), pool);

	priority(pool->priority);
	posixsrv_msgThread(pool);
	return 0;
}
