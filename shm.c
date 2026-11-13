#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>
#include <posix/idtree.h>
#include <phoenix/shm.h>

#include "posixsrv_private.h"


// #define SHM_VERBOSE
#ifdef SHM_VERBOSE
#define SHM_TRACE(fmt, ...) printf("shm:" fmt "\n", ##__VA_ARGS__)
#else
#define SHM_TRACE(fmt, ...)
#endif


struct {
	pthread_mutex_t lock;
} shm_common = {
	.lock = PTHREAD_MUTEX_INITIALIZER
};


typedef struct {
	/* object has to be first since it also acts as linkage */
	object_t object;

	char name[sizeof(SHM_PATH) + SHM_NAME_MAX];

	volatile size_t size;

	unsigned int opens;
	bool unlinked;
	bool linkDropped;
} shared_mem_t;


static request_t *shm_open_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;

	SHM_TRACE("open(%s) - refs: %u - opens(before) %u", shm_mem->name, object->refs, shm_mem->opens);

	pthread_mutex_lock(&shm_common.lock);
	shm_mem->opens++;
	pthread_mutex_unlock(&shm_common.lock);

	posixsrv_object_ref(object);
	rq_setResponse(request, EOK);
	return request;
}


static request_t *shm_truncate_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;

	SHM_TRACE("truncate(%s) - refs: %u (prev_sz=%lu, sz=%lu)", shm_mem->name, object->refs, shm_mem->size, request->msg.i.io.len);

	pthread_mutex_lock(&shm_common.lock);
	shm_mem->size = request->msg.i.io.len;
	pthread_mutex_unlock(&shm_common.lock);

	rq_setResponse(request, EOK);
	return request;
}


static request_t *shm_close_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;
	bool last;

	SHM_TRACE("close(%s) - refs: %u", shm_mem->name, object->refs);

	pthread_mutex_lock(&shm_common.lock);
	if (shm_mem->opens > 0) {
		shm_mem->opens--;
	}

	last = shm_mem->unlinked && (shm_mem->opens == 0) && shm_mem->linkDropped;
	if (last) {
		shm_mem->linkDropped = true;
	}
	pthread_mutex_unlock(&shm_common.lock);

	if (last) {
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}

	posixsrv_object_put(object);
	rq_setResponse(request, EOK);
	return request;
}


static request_t *shm_read_op(object_t *object, request_t *request)
{
#ifdef SHM_VERBOSE
	shared_mem_t *shm_mem = (shared_mem_t *)object;
#endif

	SHM_TRACE("read(%s) - refs: %u", shm_mem->name, object->refs);

	memset(request->msg.o.data, 0, request->msg.o.size);

	rq_setResponse(request, request->msg.o.size);
	return request;
}


static request_t *shm_destroy_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;
	int ret;
	bool unlinked, last;

	SHM_TRACE("destroy(%s) - refs %u - opens %u", shm_mem->name, object->refs, shm_mem->opens);

	pthread_mutex_lock(&shm_common.lock);
	unlinked = shm_mem->unlinked;
	shm_mem->unlinked = true;
	pthread_mutex_unlock(&shm_common.lock);

	if (unlinked) {
		rq_setResponse(request, -ENOENT);
		return request;
	}

	ret = destroy_dev(shm_mem->name);
	if (ret < 0) {
		rq_setResponse(request, (ret == -ENODEV) ? -ENOENT : ret);
		return request;
	}

	pthread_mutex_lock(&shm_common.lock);
	last = shm_mem->opens == 0 && !shm_mem->linkDropped;
	if (last)
		shm_mem->linkDropped = true;
	pthread_mutex_unlock(&shm_common.lock);

	if (last) {
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}

	rq_setResponse(request, EOK);
	return request;
}


static request_t *shm_unlink_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;
	bool last;

	SHM_TRACE("unlink(%s) - refs: %u", shm_mem->name, object->refs);

	pthread_mutex_lock(&shm_common.lock);
	shm_mem->unlinked = true;
	last = (shm_mem->opens == 0) && !shm_mem->linkDropped;
	if (last) {
		shm_mem->linkDropped = true;
		posixsrv_object_destroy(object);
		posixsrv_object_put(object);
	}
	pthread_mutex_unlock(&shm_common.lock);

	rq_setResponse(request, EOK);
	return request;
}


static void shm_release_op(object_t *object)
{
	free(object);
}


static request_t *shm_getAttr_op(object_t *object, request_t *request)
{
	shared_mem_t *shm_mem = (shared_mem_t *)object;

	SHM_TRACE("getAttr(%s) - refs: %u (sz=%lu)\n", shm_mem->name, object->refs, shm_mem->size);

	if (request->msg.i.attr.type != 3 /* atSize */) {
		rq_setResponse(request, -EINVAL);
		return request;
	}

	pthread_mutex_lock(&shm_common.lock);
	request->msg.o.attr.val = (off_t)shm_mem->size;
	request->msg.o.err = EOK;
	pthread_mutex_unlock(&shm_common.lock);

	return request;
}


static const operations_t shm_ops = {
	.open = shm_open_op,
	.truncate = shm_truncate_op,
	.close = shm_close_op,
	.read = shm_read_op, /* Required to populate mapping of _vm_object_t */
	.destroy = shm_destroy_op,
	.unlink = shm_unlink_op,
	.getattr = shm_getAttr_op,
	.release = shm_release_op,
};


static int shm_create(const char *name, ssize_t len, int *id)
{
	shared_mem_t *shm_mem;
	int ret;

	if (NULL == name || name[len - 1] != '\0') {
		return -EINVAL;
	}

	if (*name == '/') {
		name++;
	}

	if (*name == '\0' || strchr((char *)name, '/') != NULL) {
		return -EINVAL;
	}

	shm_mem = malloc(sizeof(*shm_mem));
	if (NULL == shm_mem) {
		return -ENOMEM;
	}

	len = snprintf(shm_mem->name, sizeof(shm_mem->name), "%s%s", SHM_PATH, name);
	if (len < 0 || (size_t)len >= sizeof(shm_mem->name)) {
		free(shm_mem);
		return -ENAMETOOLONG;
	}

	shm_mem->opens = 0;
	shm_mem->size = 0UL;
	shm_mem->unlinked = false;
	shm_mem->linkDropped = false;

	posixsrv_object_create(&shm_mem->object, &shm_ops);
	ret = posixsrv_object_link(&shm_mem->object, shm_mem->name);
	if (ret < 0) {
		SHM_TRACE("Failed to create shared memory object\n");
		posixsrv_object_destroy(&shm_mem->object);
		posixsrv_object_put(&shm_mem->object);
		return ret;
	}

	*id = posixsrv_object_id(&shm_mem->object);

	/* Similarly to the semaphore implementation we drop mode_t here */

	return EOK;
}


static request_t *shm_create_op(object_t *srv, request_t *request)
{
	int id = 0, ret;

	ret = shm_create(request->msg.i.data, (ssize_t)request->msg.i.size, &id);

	SHM_TRACE("create: id = %d, ret = %d", id, ret);

	rq_setResponse(request, ret);
	if (EOK == ret) {
		request->msg.o.create.oid.port = posixsrv_port();
		request->msg.o.create.oid.id = id;
	}

	return request;
}


static const operations_t shm_control_ops = {
	.create = shm_create_op
};


int shm_init(void)
{
	object_t *object;
	int err;

	object = malloc(sizeof(*object));
	if (NULL == object) {
		SHM_TRACE("couldnt allocate new object");
		return -ENOMEM;
	}

	err = mkdir(SHM_PATH, 0777);
	if (err != 0 && errno != EEXIST) {
		SHM_TRACE("failed to create shm namespace");
		err = -errno;
		pthread_mutex_destroy(&shm_common.lock);
		free(object);
		return err;
	}

	posixsrv_object_create(object, &shm_control_ops);
	err = posixsrv_object_link(object, SHMCTL_PATH);
	posixsrv_object_put(object);
	return err;
}
