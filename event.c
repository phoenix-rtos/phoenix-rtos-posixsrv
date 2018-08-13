/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX implementation - events (poll/select)
 *
 * Copyright 2018 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <sys/msg.h>
#include <sys/file.h>
#include <sys/threads.h>
#include <sys/rb.h>
#include <sys/list.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "posix/idtree.h"
#include "posixsrv_private.h"
#include "posixsrv.h"


#define INITIAL_EVENT_BUF_COUNT 16
#define GROW_EVENT_BUF(sz) (2 * (sz))


typedef struct _evqueue_t {
	struct _evqueue_t *next, *prev;

	object_t object;
	handle_t lock;
	request_t *requests;
	struct _evnote_t *notes;
} evqueue_t;


typedef struct _evnote_t {
	struct _eventry_t *entry;
	struct _evnote_t *next, *prev;
	struct _evqueue_t *queue;
	struct _evnote_t *queue_next, *queue_prev;

	unsigned short mask;
	unsigned short pend;
	unsigned short enabled;
	unsigned short oneshot;

	unsigned flags;

	struct {
		unsigned flags;
		unsigned count;
		unsigned data;
	} pending[16];
} evnote_t;


typedef struct _eventry_t {
	rbnode_t node;
	oid_t oid;
	handle_t lock;
	unsigned refs;

	unsigned short mask;
	evnote_t *notes;
} eventry_t;


static handler_t sink_create_op, sink_write_op, sink_open_op, sink_close_op;
static handler_t queue_read_op, queue_write_op, queue_open_op, queue_close_op;


static operations_t sink_ops = {
	.handlers = { NULL },
	.open = sink_open_op,
	.close = sink_close_op,
	.write = sink_write_op,
	.create = sink_create_op,
};


static operations_t queue_ops = {
	.handlers = { NULL },
	.open = queue_open_op,
	.close = queue_close_op,
	.write = queue_write_op,
	.read = queue_read_op,
};


static struct {
	object_t sink;
	handle_t lock;
	rbtree_t notes;
} event_common;


static int event_cmp(rbnode_t *n1, rbnode_t *n2)
{
	eventry_t *e1 = lib_treeof(eventry_t, node, n1);
	eventry_t *e2 = lib_treeof(eventry_t, node, n2);

	if (e1->oid.port != e2->oid.port)
		return e1->oid.port > e2->oid.port ? 1 : -1;

	if (e1->oid.id != e2->oid.id)
		return e1->oid.id > e2->oid.id ? 1 : -1;

	return 0;
}


static void queue_add(evqueue_t *queue, evqueue_t **wakeq)
{
	mutexLock(event_common.lock);
	if (queue->next == NULL)
		LIST_ADD(wakeq, queue);
	mutexUnlock(event_common.lock);
}


static eventry_t *_entry_find(oid_t *oid)
{
	eventry_t find, *entry;
	memcpy(&find.oid, oid, sizeof(oid_t));
	if ((entry = lib_treeof(eventry_t, node, lib_rbFind(&event_common.notes, &find.node))) != NULL)
		entry->refs++;
	return entry;
}


static eventry_t *entry_find(oid_t *oid)
{
	eventry_t *entry;

	mutexLock(event_common.lock);
	entry = _entry_find(oid);
	mutexUnlock(event_common.lock);
	return entry;
}


static void _entry_remove(eventry_t *entry)
{
	resourceDestroy(entry->lock);
	lib_rbRemove(&event_common.notes, &entry->node);
	free(entry);
}


static eventry_t *_entry_new(oid_t *oid)
{
	eventry_t *entry;

	if ((entry = calloc(1, sizeof(eventry_t))) == NULL)
		return NULL;

	memcpy(&entry->oid, oid, sizeof(oid_t));
	mutexCreate(&entry->lock);
	entry->refs = 2;
	lib_rbInsert(&event_common.notes, &entry->node);
	return entry;
}


static eventry_t *entry_get(oid_t *oid)
{
	eventry_t *entry;

	mutexLock(event_common.lock);
	if ((entry = _entry_find(oid)) == NULL)
		entry = _entry_new(oid);
	mutexUnlock(event_common.lock);
	return entry;
}


static void entry_put(eventry_t *entry)
{
	mutexLock(event_common.lock);
	if (!--entry->refs)
		_entry_remove(entry);
	mutexUnlock(event_common.lock);
}


static void _entry_register(eventry_t *entry, event_t *event, evqueue_t **wakeq)
{
	evnote_t *note;
	unsigned short typebit;

	typebit = 1 << event->type;

	if (!(entry->mask & typebit))
		return;

	note = entry->notes;
	do {
		if (note->mask & typebit) {
			if (note->pend & typebit) {
				note->pending[event->type].flags |= event->flags;
				note->pending[event->type].count += event->count;
			}
			else {
				note->pend |= typebit;
				note->pending[event->type].flags = event->flags;
				note->pending[event->type].count = event->count;

				queue_add(note->queue, wakeq);
			}

			note->pending[event->type].data = event->data;
		}

		note = note->next;
	} while (note != entry->notes);
}


static void _entry_notify(eventry_t *entry)
{
	msg_t msg;

	msg.type = mtSetAttr;
	msg.i.attr.type = atEventMask;
	memcpy(&msg.i.attr.oid, &entry->oid, sizeof(oid_t));
	msg.i.attr.val = entry->mask;

	msg.i.data = msg.o.data = NULL;
	msg.i.size = msg.o.size = 0;

	msgSend(entry->oid.port, &msg);
}


static void _entry_recalculate(eventry_t *entry)
{
	evnote_t *note;
	unsigned short mask = 0;

	note = entry->notes;
	do {
		mask |= note->mask;
		note = note->next;
	} while (note != entry->notes);

	if (mask != entry->mask)
		_entry_notify(entry);

	entry->mask = mask;
}


static evnote_t *_note_new(evqueue_t *queue, eventry_t *entry)
{
	evnote_t *note;

	if ((note = calloc(1, sizeof(evnote_t))) == NULL)
		return NULL;

	note->entry = entry;
	note->queue = queue;

	LIST_ADD(&entry->notes, note);
	LIST_ADD_EX(&queue->notes, note, queue_next, queue_prev);

	return note;
}


static void _note_remove(evqueue_t *queue, evnote_t *note)
{
	LIST_REMOVE(&note->entry->notes, note);
	entry_put(note->entry);

	LIST_REMOVE_EX(&queue->notes, note, queue_next, queue_prev);
	free(note);
}


static void _note_merge(evnote_t *note, evsub_t *sub)
{
	if (note->flags & evAdd) {
		note->mask |= sub->types;
		note->enabled |= sub->types;
	}

	if (note->flags & evDelete) {
		note->mask &= ~sub->types;
		note->enabled &= ~sub->types;
	}

	if (note->flags & evEnable)
		note->enabled |= sub->types;

	if (note->flags & evDisable)
		note->enabled &= ~sub->types;

	if (note->flags & evOneshot)
		note->oneshot |= sub->types;

	if (note->flags & evClear)
		note->pend &= ~sub->types;
}


static int _event_subscribe(evqueue_t *queue, evsub_t *sub, int count)
{
	evnote_t *note;
	eventry_t *entry;
	unsigned short mask;

	while (count--) {
		if ((note = queue->notes) != NULL) {
			do {
				entry = note->entry;
				if (!memcmp(&entry->oid, &sub->oid, sizeof(oid_t))) {
					mutexLock(entry->lock);
					goto got_note;
				}
				note = note->queue_next;
			} while (note != queue->notes);
		}

		/* this reference is donated to the new note created below */
		if ((entry = entry_get(&sub->oid)) == NULL)
			return -ENOMEM;

		mutexLock(entry->lock);

		if ((note = _note_new(queue, entry)) == NULL) {
			mutexUnlock(entry->lock);
			entry_put(entry);
			return -ENOMEM;
		}

	got_note:
		mask = note->mask;
		_note_merge(note, sub);

		if (note->mask != mask) {
			if (mask & ~note->mask) {
				/* change might clear some bits */
				_entry_recalculate(entry);
			}
			else if ((entry->mask & note->mask) != note->mask) {
				entry->mask |= note->mask;
				_entry_notify(entry);
			}
		}

		if (!note->mask)
			_note_remove(queue, note);

		mutexUnlock(entry->lock);
		sub++;
	}

	return EOK;
}


static void queue_wakeup(evqueue_t *queue);


void event_register(event_t *events, int count)
{
	event_t *event;
	eventry_t *entry;
	evqueue_t *wakeq;
	int i = 0;

	for (i = 0; i < count; ++i) {
		event = events + i;

		if ((entry = entry_find(&event->oid)) == NULL)
			continue;

		mutexLock(entry->lock);
		_entry_register(entry, event, &wakeq);
		mutexUnlock(entry->lock);

		entry_put(entry);
	}

	queue_wakeup(wakeq);
}


static evqueue_t *queue_create(void)
{
	evqueue_t *queue;

	if ((queue = calloc(1, sizeof(evqueue_t))) == NULL)
		return NULL;

	if (mutexCreate(&queue->lock) < 0) {
		free(queue);
		return NULL;
	}

	object_create(&queue->object, &queue_ops);
	return queue;
}


static int _event_read(evqueue_t *queue, event_t *event, int eventcnt)
{
	int type, i = 0;
	unsigned short typebit;
	evnote_t *note;

	while (i < eventcnt) {
		note = queue->notes;

		do {
			mutexLock(note->entry->lock);
			for (type = 0; type < sizeof(note->pending) / sizeof(*note->pending) && i < eventcnt; ++type) {
				typebit = 1 << type;

				if (note->pend & note->mask & typebit) {
					memcpy(&event->oid, &note->entry->oid, sizeof(oid_t));
					event->type = type;
					event->flags = note->pending[type].flags;
					event->data = note->pending[type].data;
				}

				note->pend &= ~typebit;
				memset(note->pending + type, 0, sizeof(note->pending[type]));

				++i;
				++event;
			}
			mutexUnlock(note->entry->lock);

			note = note->queue_next;
		} while (note != queue->notes && i < eventcnt);
	}

	return i;
}


static void queue_wakeup(evqueue_t *queue)
{
	request_t *r, *filled = NULL, *empty;
	int count;

	while (queue != NULL) {
		empty = NULL;

		mutexLock(queue->lock);
		while (queue->requests != NULL) {
			r = queue->requests;
			LIST_REMOVE(&queue->requests, r);

			if ((count = _event_read(queue, (event_t *)r->msg.o.data, r->msg.o.size / sizeof(event_t)))) {
				LIST_ADD(&filled, r);
				r->msg.o.io.err = count;
			}
			else {
				LIST_ADD(&empty, r);
			}
		}
		queue->requests = empty;
		mutexUnlock(queue->lock);

		mutexLock(event_common.lock);
		LIST_REMOVE(&queue, queue);
		mutexUnlock(event_common.lock);
	}

	while ((r = filled) != NULL) {
		LIST_REMOVE(&filled, r);
		rq_wakeup(r, r->msg.o.io.err);
	}
}


static request_t *queue_open_op(object_t *o, request_t *r)
{
	/* TODO */
	return r;
}


static request_t *queue_close_op(object_t *o, request_t *r)
{
	/* TODO */
	return r;
}


static request_t *_queue_readwrite(evqueue_t *queue, request_t *r)
{
	int count;
	evsub_t *subs;

	if (r->msg.i.size) {
		if (r->msg.i.size % sizeof(evsub_t)) {
			r->msg.o.io.err = -EINVAL;
			return r;
		}

		subs = (evsub_t *)r->msg.i.data;
		count = r->msg.i.size / sizeof(evsub_t);
		_event_subscribe(queue, subs, count);
	}

	if (r->msg.o.size) {
		if (r->msg.o.size % sizeof(event_t)) {
			r->msg.o.io.err = -EINVAL;
			return r;
		}

		count = _event_read(queue, (event_t *)r->msg.o.data, r->msg.o.size / sizeof(event_t));
		if (!count) {
			LIST_ADD(&queue->requests, r);
			r = NULL;
		}
		else {
			r->msg.o.io.err = count;
		}
	}

	return r;
}


static request_t *queue_write_op(object_t *o, request_t *r)
{
	evqueue_t *queue = (evqueue_t *)o;
	mutexLock(queue->lock);
	r = _queue_readwrite(queue, r);
	mutexUnlock(queue->lock);
	return r;
}


static request_t *queue_read_op(object_t *o, request_t *r)
{
	evqueue_t *queue = (evqueue_t *)o;
	mutexLock(queue->lock);
	r = _queue_readwrite(queue, r);
	mutexUnlock(queue->lock);
	return r;
}


static request_t *sink_open_op(object_t *o, request_t *r)
{
	return r;
}


static request_t *sink_close_op(object_t *o, request_t *r)
{
	return r;
}


static request_t *sink_create_op(object_t *o, request_t *r)
{
	evqueue_t *queue;

	if ((queue = queue_create()) == NULL) {
		r->msg.o.create.err = -ENOMEM;
	}
	else {
		r->msg.o.create.err = EOK;
		r->msg.o.create.oid.port = srv_port();
		r->msg.o.create.oid.id = object_id(&queue->object);
	}

	return r;
}


static request_t *sink_write_op(object_t *o, request_t *r)
{
	event_t stackbuf[64];
	event_t *events;
	unsigned eventcnt;

	if (r->msg.i.size % sizeof(event_t)) {
		r->msg.o.io.err = -EINVAL;
		return r;
	}

	if (r->msg.i.size <= sizeof(stackbuf)) {
		events = stackbuf;
	}
	else if ((events = malloc(r->msg.i.size)) == NULL) {
		r->msg.o.io.err = -ENOMEM;
		return r;
	}

	eventcnt = r->msg.i.size / sizeof(event_t);
	memcpy(events, r->msg.i.data, r->msg.i.size);
	rq_wakeup(r, EOK);

	event_register(events, eventcnt);

	if (eventcnt > sizeof(stackbuf) / sizeof(event_t))
		free(events);

	return NULL;
}


int event_init(void)
{
	if (mutexCreate(&event_common.lock) < 0)
		return -ENOMEM;

	lib_rbInit(&event_common.notes, event_cmp, NULL);
	object_create(&event_common.sink, &sink_ops);
	return object_link(&event_common.sink, "/dev/events");
}