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

/* tunable parameters */
#define _CACHE_LINE_SIZE	64
#define _BACTRACE_SIZE		1024

/*
 * Dump the data object type i.e. it's either DATA or heap.
 */
static inline void _cache_dump_address_type(void *addr, size_t size)
{
	size_t heap;

	/* try and get ptr type */
	heap = malloc_usable_size(addr);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);
}

/*
 * Dump the stack backtrace.
 */
static inline void _cache_dump_backtrace(void)
{
	void *backtrace_data[_BACTRACE_SIZE];
	int backtrace_size;

	backtrace_size = backtrace(backtrace_data, _BACTRACE_SIZE);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);
}

/*
 * Calculate the size of the cache operation in bytes (i.e. aligned to the
 * cache line size)
 */
static inline size_t _cache_op_size(size_t req_size)
{
	if (req_size % _CACHE_LINE_SIZE)
		return req_size + _CACHE_LINE_SIZE - (req_size % _CACHE_LINE_SIZE);
	else
		return req_size;
}

/*
 * Calculate the alignment offset of the cache operation in bytes (i.e. aligned
 * to the cache line size)
 */
static inline long _cache_op_offset(void *base, void *addr)
{
	unsigned long offset;

	assert(addr >= base);

	offset = (unsigned long)addr - (unsigned long)base;

	if (offset % _CACHE_LINE_SIZE)
		return -(offset % _CACHE_LINE_SIZE);
	else
		return 0;
}

/*
 * Get the current core ID from the thread ID. There will be a 1:1 mapping
 * between thread and core in testbench usage.
 */
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

/*
 * Find elem based on cache address and core number.
 */
static inline struct cache_elem *_cache_get_elem_from_cache(void *addr, int core)
{
	struct cache_elem *elem;
	int i;

	/* find elem with cache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == addr)
			return elem;
	}

	/* not found */
	return NULL;
}

/*
 * Find elem based on uncache address.
 */
static inline struct cache_elem *_cache_get_elem_from_uncache(void *addr)
{
	struct cache_elem *elem;
	int i;

	/* find elem with cache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->uncache == addr)
			return elem;
	}

	/* not found */
	return NULL;
}

/*
 * Find first free elem.
 */
static inline struct cache_elem *_cache_get_free_elem(void)
{
	struct cache_elem *elem;
	int i;

	/* find elem with cache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->valid)
			continue;
		return elem;
	}

	/* not found */
	return NULL;
}

#if 0
/*
 * Configure and allocate new data section
 */
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
#endif

/*
 * Create and setup a new ucache entry
 */
static inline void _cache_set_udata(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type,
		void *address, size_t size, int alloc)
{
	elem->func = func;
	elem->line = line;
	elem->type = type;
	elem->core = core;
	elem->size = size;

	/* are we using client copy or do we allocate our copy */
	if (alloc)
		elem->uncache = malloc(size);
	else
		elem->uncache = address;
}

/*
 * Create and setup a new ccache entry
 */
static inline void _cache_new_data(struct cache_elem *elem, int core,
		const char *func, int line, enum cache_data_type type,
		void *address, size_t size, int alloc)
{
	struct cache_entry *centry = &elem->cache[core];

	centry->func = func;
	centry->line = line;
	centry->type = type;

	/* are we using client copy or do we allocate our copy */
	if (alloc)
		centry->data = malloc(size);
	else
		centry->data = address;

	centry->snapshot = malloc(size);

	/* memcpy and take a snapshot of original data for comparison later */
	memcpy(centry->snapshot, centry->data, size);
}

/*
 * Create a new elem from a cached address
 */
static inline struct cache_elem *_cache_new_celem(void *addr, int core,
		const char *func, int line, enum cache_data_type type, size_t size)
{
	struct cache_elem *elem;
	int i;

	elem = _cache_get_free_elem();
	if (!elem) {
		fprintf(stderr, "!!no free elems for ccache!\n");
		return NULL;
	}

	/* create the uncache mapping  */
	_cache_set_udata(elem, core, func, line, type, addr, size, 1);

	/* create the cache mappings - we only alloc for new entries */
	for (i = 0; i < CONFIG_CORE_COUNT; i++) {
		_cache_new_data(elem, core, func, line, type, addr, size,
				i == core ? 0 : 1);
	}
	return elem;
}

/*
 * Create a new elem from a uncached address
 */
static inline struct cache_elem *_cache_new_uelem(void *addr, int core,
		const char *func, int line, enum cache_data_type type, size_t size)
{
	struct cache_elem *elem;
	int i;

	elem = _cache_get_free_elem();
	if (!elem) {
		fprintf(stderr, "!!no free elems for ucache!\n");
		return NULL;
	}

	/* create the uncache mapping  */
	_cache_set_udata(elem, core, func, line, type, addr, size, 0);

	/* create the cache mappings */
	for (i = 0; i < CONFIG_CORE_COUNT; i++) {
		_cache_new_data(elem, core, func, line, type, addr, size, 1);
	}
	return elem;
}

/*
 * Free a cache element.
 */
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

/*
 * Invalidate cache elem from uncache mapping.
 */
static inline void _cache_elem_invalidate(struct cache_elem *elem, int core,
		void *addr, size_t size, const char *func, int line)
{
	struct cache_entry *centry = &elem->cache[core];
	int i;
	long offset = _cache_op_offset(centry->data, addr);
	size_t inv_size = _cache_op_size(size);

	/* TODO check coherency */
	for (i = 0; i < CONFIG_CORE_COUNT; i++) {
		centry = &elem->cache[i];

		/* copy offset and size are aligned to cache lines */
		memcpy((char*)centry->data + offset, (char*)elem->uncache + offset, inv_size);
	}

	fprintf(stdout, "inv: core %d offset %ld size %zu\n", core, offset, inv_size);
}

/*
 * Writeback cache elem from core N to uncache mapping.
 */
static inline void _cache_elem_writeback(struct cache_elem *elem, int core,
		void *addr, size_t size, const char *func, int line)
{
	struct cache_entry *centry = &elem->cache[core];
	long offset = _cache_op_offset(centry->data, addr);
	size_t inv_size = _cache_op_size(size);

	/* copy to uncache  - use size as GCC spots the boundaries */
	memcpy((char*)elem->uncache + offset, (char*)centry->data + offset, size);

	fprintf(stdout, "wb: core %d offset %ld size %zu\n", core, offset, inv_size);
}

static inline void _dcache_writeback_region(void *addr, size_t size, const char *func, int line)
{
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t phy_size = _cache_op_size(size);

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache wb %zu bytes at %s %d\n", size, func, line);
	if (size != phy_size)
		fprintf(stdout, "  warning non alignment ! - wb is really %zu bytes\n", phy_size);

	_cache_dump_address_type(addr, size);
	_cache_dump_backtrace();

	/* are we writing back an existing cache object ? */
	elem = _cache_get_elem_from_cache(addr, core);
	if (!elem) {
		/* no elem found so create one */
		elem = _cache_new_celem(addr, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
		if (!elem)
			return;
	}

	_cache_elem_writeback(elem, core, addr, size, func, line);
}

static inline void _dcache_invalidate_region(void *addr, size_t size, const char *func, int line)
{
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t phy_size = _cache_op_size(size);

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache inv %zu bytes at %s %d\n", size, func, line);
	if (size != phy_size)
		fprintf(stdout, "  warning non alignment ! - inv is really %zu bytes\n", phy_size);

	_cache_dump_address_type(addr, size);
	_cache_dump_backtrace();

	/* are we invalidating an existing cache object ? */
	elem = _cache_get_elem_from_cache(addr, core);
	if (!elem) {
		/* no elem found so create one */
		elem = _cache_new_celem(addr, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
		if (!elem)
			return;
	}

	_cache_elem_invalidate(elem, core, addr, size, func, line);
}

static inline void _icache_invalidate_region(void *addr, size_t size, const char *func, int line)
{
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t phy_size = _cache_op_size(size);

	fprintf(stdout, "\n\n");

	fprintf(stdout, "icache inv %zu bytes at %s %d\n", size, func, line);
	if (size != phy_size)
		fprintf(stdout, "  warning non alignment ! - inv is really %zu bytes\n", phy_size);

	_cache_dump_address_type(addr, size);
	_cache_dump_backtrace();

	/* are we invalidating an existing cache object ? */
	elem = _cache_get_elem_from_cache(addr, core);
	if (!elem) {
		/* no elem found so create one */
		elem = _cache_new_celem(addr, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
		if (!elem)
			return;
	}

	_cache_elem_invalidate(elem, core, addr, size, func, line);
}

static inline void _dcache_writeback_invalidate_region(void *addr,
	size_t size, const char *func, int line)
{
	int core = _cache_find_core(func, line);
	struct cache_elem *elem;
	size_t phy_size = _cache_op_size(size);

	fprintf(stdout, "\n\n");

	fprintf(stdout, "dcache wb+inv %zu bytes at %s %d\n", size, func, line);
	if (size != phy_size)
		fprintf(stdout, "  warning non alignment ! - wb+inv is really %zu bytes\n", phy_size);

	_cache_dump_address_type(addr, size);
	_cache_dump_backtrace();

	/* are we invalidating an existing cache object ? */
	elem = _cache_get_elem_from_cache(addr, core);
	if (!elem) {
		/* no elem found so create one */
		elem = _cache_new_celem(addr, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
		if (!elem)
			return;
	}

	_cache_elem_writeback(elem, core, addr, size, func, line);
	_cache_elem_invalidate(elem, core, addr, size, func, line);
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
