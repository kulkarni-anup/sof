/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#ifdef __SOF_LIB_CACHE_H__

#ifndef __ARCH_LIB_CACHE_H__
#define __ARCH_LIB_CACHE_H__

#include <stddef.h>
#include <pthread.h>

/*
 * Check logic will memchk contents of all cache entres and
 * report differences on every tick.
 *
 * snapshot is also compared agiants cache and uncache to spot
 * local changes that are incoherent
 */

#define HOST_CACHE_ELEMS	1024
#define HOST_CACHE_DATA_SIZE	4096

enum cache_action {
	CACHE_ACTION_NONE	= 0,
	CACHE_ACTION_WB		= 1,
	CACHE_ACTION_INV	= 2,
	CACHE_ACTION_WB_INV	= 3,
};

enum cache_data_type {
	CACHE_DATA_TYPE_HEAP_UNCACHE 	= 0,
	CACHE_DATA_TYPE_HEAP_CACHE 	= 1,
	CACHE_DATA_TYPE_DATA_UNCACHE 	= 2,
	CACHE_DATA_TYPE_DATA_CACHE 	= 3,
};

/* per core cache context */
struct cache_entry {
	void *data;
	void *snapshot;
	int line; 		/* line of last action */
	const char *func; 	/*func of last action */
	enum cache_action action; 	/* last action */
	enum cache_data_type type;	/* heap, data */
	const char *symbols;		/* last stack usage */
};

/* uncache to cache based mapping */
struct cache_elem {
	int valid;
	void *uncache; 		/* align on cache size */
	size_t size;		/* size of mapping */
	int line; 		/* allocator line */
	const char *func; 	/* allocator func */
	int core;		/* first use core */
	enum cache_data_type type;	/* heap, data */
	struct cache_entry cache[CONFIG_CORE_COUNT];
};

struct cache_context {
	int num_elems;
	pthread_t thread_id[CONFIG_CORE_COUNT];
	struct cache_elem elem[HOST_CACHE_ELEMS];
};

extern struct cache_context *host_cache;

static inline struct cache_elem *_cache_new_elem(void)
{
	struct cache_elem *elem;
	int i;

	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (!elem->valid) {
			elem->valid = 1;
			return elem;
		}
	}

	fprintf(stderr, "!!no new cache elems!\n");
	return NULL;
}

static inline void _cache_free_elem(struct cache_elem *elem)
{
	int core;

	/* TODO check coherency */

	for (core = 0; core < CONFIG_CORE_COUNT; core++) {
		if (elem->cache[core].data) {
			free(elem->cache[core].data);
			free(elem->cache[core].snapshot);
		}
	}
	free(elem->uncache);
	bzero(elem, sizeof(*elem));
}

/* allocate new data section */
static inline void *_cache_new_udata(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type, size_t size)
{
	elem->func = func;
	elem->line = line;
	elem->type = type;
	elem->core = core;
	elem->size = size;
	elem->uncache = malloc(size);

	return elem->uncache;
}

static inline void *_cache_new_cdata(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type, size_t size)
{
	struct cache_entry *centry = &elem->cache[core];

	centry->func = func;
	centry->line = line;
	centry->action = CACHE_ACTION_NONE;
	centry->type = type;

	/* TODO: we can inject tracking data here or zeors */
	centry->data = malloc(size);
	centry->snapshot = malloc(size);

	/* memcpy and take a snapshot of original data for comparison later */
	memcpy(centry->snapshot, centry->data, size);

	return centry->data;
}

static inline int _cache_find_core(const char *func, int line)
{
	int core;
	pthread_t thread_id;

	thread_id = pthread_self();

	/* find core */
	for (core = 0; core < CONFIG_CORE_COUNT; core++) {
		if (host_cache->thread_id[core] == thread_id)
			return core;
	}

	fprintf(stderr, "error: cant find core for %lu - DEAD at %s:%d\n",
		thread_id, func, line);
	assert(0);
	return -1;
}

static inline void _cache_set_udata(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type,
		void *address, size_t size)
{
	elem->func = func;
	elem->line = line;
	elem->type = type;
	elem->core = core;
	elem->size = size;
	elem->uncache = address;
}

static inline void _cache_set_cdata(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type,
		void *address, size_t size)
{
	struct cache_entry *centry = &elem->cache[core];

	centry->func = func;
	centry->line = line;
	centry->type = type;
	centry->data = address;

	centry->snapshot = malloc(size);

	/* memcpy and take a snapshot of original data for comparison later */
	memcpy(centry->snapshot, centry->data, size);
}


static inline void _dcache_writeback_region(void *addr, size_t size, const char *func, int line)
{
	void *backtrace_data[1024];
	int backtrace_size;
	int i;
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t heap;

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache wb %zu bytes at %s %d\n", size, func, line);
	if (size % 64)
		fprintf(stdout, "  warning non alignment ! - wb is really %zu bytes\n", size + 64 - (size %64));

	/* try and get ptr type */
	heap = malloc_usable_size(addr);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == addr) {
			fprintf(stdout, "wb: %s() line %d\n", func, line);
		}
	}
}

static inline void _dcache_invalidate_region(void *addr, size_t size, const char *func, int line)
{
	void *backtrace_data[1024];
	int backtrace_size;
	int i;
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t heap;

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache inv %zu bytes at %s %d\n", size, func, line);
	if (size % 64) {
		size = size + 64 - (size % 64);
		fprintf(stdout, "  warning non alignment ! - inv is really %zu bytes\n", size);
	}

	/* try and get ptr type */
	heap = malloc_usable_size(addr);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == addr) {
			fprintf(stdout, "inv: %s() line %d\n", func, line);
			goto found;
		}
	}
fprintf(stdout, "%s %d\n", __func__, __LINE__);
	/* no elem found so create one */
	elem = _cache_new_elem();
	if (!elem)
		return;
	fprintf(stdout, "%s %d\n", __func__, __LINE__);
	/* set a new uncache mapping TODO: use orig size ?? */
	_cache_set_cdata(elem, core, func, line, CACHE_DATA_TYPE_DATA_UNCACHE, addr, size);

found:
fprintf(stdout, "%s %d\n", __func__, __LINE__);
	/* TODO do coherency checking */
	if (elem->uncache)
		memcpy(elem->uncache, elem->cache[core].data, size);
	fprintf(stdout, "%s %d\n", __func__, __LINE__);
}

static inline void _icache_invalidate_region(void *addr, size_t size, const char *func, int line)
{
	void *backtrace_data[1024];
	int backtrace_size;
	int i;
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t heap;

	fprintf(stdout, "\n\n");

	fprintf(stdout, "icache inv %zu bytes at %s %d\n", size, func, line);
	if (size % 64)
		fprintf(stdout, "  warning non alignment ! - inv is really %zu bytes\n", size + 64 - (size %64));

	/* try and get ptr type */
	heap = malloc_usable_size(addr);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == addr) {
			fprintf(stdout, "invI: %s() line %d\n", func, line);
		}
	}
}

static inline void _dcache_writeback_invalidate_region(void *addr,
	size_t size, const char *func, int line)
{
	void *backtrace_data[1024];
	int backtrace_size;
	int i;
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t heap;

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache wb+inv %zu bytes at %s %d\n", size, func, line);
	if (size % 64)
		fprintf(stdout, "  warning non alignment ! - wb+inv is really %zu bytes\n", size + 64 - (size %64));

	/* try and get ptr type */
	heap = malloc_usable_size(addr);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == addr) {
			fprintf(stdout, "wb-inv: %s() line %d\n", func, line);
		}
	}
}

#define dcache_writeback_region(addr, size) \
	_dcache_writeback_region(addr, size, __func__, __LINE__)

#define dcache_invalidate_region(addr, size) \
	_dcache_invalidate_region(addr, size, __func__, __LINE__)

#define icache_invalidate_region(addr, size) \
	_icache_invalidate_region(addr, size, __func__, __LINE__)

#define dcache_writeback_invalidate_region(addr, size) \
	_dcache_writeback_invalidate_region(addr, size, __func__, __LINE__)

#if 0
static inline void dcache_writeback_region(void *addr, size_t size) {}
static inline void dcache_invalidate_region(void *addr, size_t size) {}
static inline void icache_invalidate_region(void *addr, size_t size) {}
static inline void dcache_writeback_invalidate_region(void *addr,
	size_t size) {}
#endif
#endif /* __ARCH_LIB_CACHE_H__ */

#else

#error "This file shouldn't be included from outside of sof/lib/cache.h"

#endif /* __SOF_LIB_CACHE_H__ */
