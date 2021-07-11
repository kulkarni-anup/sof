/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#ifdef __SOF_LIB_MEMORY_H__

#ifndef __PLATFORM_LIB_MEMORY_H__
#define __PLATFORM_LIB_MEMORY_H__

#include <inttypes.h>
#include <stddef.h>

#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <execinfo.h>
#include <sof/debug/panic.h>
#include <sof/lib/cache.h>

struct sof;

#define PLATFORM_DCACHE_ALIGN	sizeof(void *)

#define HEAP_BUFFER_SIZE	(1024 * 128)
#define SOF_STACK_SIZE		0x1000

uint8_t *get_library_mailbox(void);

#define MAILBOX_BASE	get_library_mailbox()

#define PLATFORM_HEAP_SYSTEM		2
#define PLATFORM_HEAP_SYSTEM_RUNTIME	1
#define PLATFORM_HEAP_RUNTIME		1
#define PLATFORM_HEAP_BUFFER		3
#define PLATFORM_HEAP_SYSTEM_SHARED	1
#define PLATFORM_HEAP_RUNTIME_SHARED	1

#define SHARED_DATA

/*
 * Use uncache address from caller and return cache[core] address. This can
 * result in.
 *
 * 1) Creating a new cache mapping for a heap object.
 * 2) Creating a new cache and unache mapping for a DATA section object.
 */
static inline void *_uncache_to_cache(void *address, const char *func, int line,
		size_t size)
{
	struct cache_elem *elem;
	int core = _cache_find_core(func, line);
	int i;
	void *cache_addr;
	void *backtrace_data[1024];
	int backtrace_size;
	size_t heap;

	fprintf(stdout, "\n\n");

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->uncache == address) {
			fprintf(stdout, "uncache -> cache: %s() line %d\n", func, line);
			cache_addr = elem->cache[core].data;
			goto found_uncache;
		}
	}

	/* uncache area not found so this must be DATA section*/
	fprintf(stdout, "uncache -> cache: %s() line %d\n new DATA object\n", func, line);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* try and get ptr type */
	heap = malloc_usable_size(address);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);

	/* find a new elem for this new mapping */
	elem = _cache_new_elem();
	if (!elem)
		return NULL;

	/* set a new uncache mapping */
	_cache_set_udata(elem, core, func, line, CACHE_DATA_TYPE_DATA_UNCACHE, address, size);

	/* get a cache address for the new uncache mapping */
	cache_addr = _cache_new_cdata(elem, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
	if (!cache_addr)
		return cache_addr;

found_uncache:
	return cache_addr;
}

#define uncache_to_cache(address)	\
	_uncache_to_cache(address, __func__, __LINE__, sizeof(*address))

/*
 * Use uncache address from caller and return cache[core] address. This can
 * result in.
 *
 * 1) Creating a new cache mapping for a heap object.
 * 2) Creating a new cache and unache mapping for a DATA section object.
 */
static inline void *_cache_to_uncache(void *address, const char *func, int line,
		size_t size)
{
	struct cache_elem *elem;
	int core = _cache_find_core(func, line);
	int i;
	void *uncache_addr;
	void *backtrace_data[1024];
	int backtrace_size;
	size_t heap;

	fprintf(stdout, "\n\n");

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->cache[core].data == address) {
			uncache_addr = elem->uncache;
			fprintf(stdout, "cache -> uncache: %s() line %d\n", func, line);
			if (!uncache_addr)
				goto new_uncache;
			goto found_uncache;
		}
	}

	/* uncache area not found so this must be DATA section*/
	fprintf(stdout, "cache -> uncache: %s() line %d\n new object size %zu\n", func, line, size);

	backtrace_size = backtrace(backtrace_data, 1024);
	backtrace_symbols_fd(backtrace_data, backtrace_size, 1);

	/* try and get ptr type */
	heap = malloc_usable_size(address);
	if (!heap)
		fprintf(stdout, " object is DATA %zu\n", size);
	else
		fprintf(stdout, " object is HEAP %zu\n", size);


	/* find a new elem for this new mapping */
	elem = _cache_new_elem();
	if (!elem)
		return NULL;

	/* set a new uncache mapping */
	_cache_set_cdata(elem, core, func, line, CACHE_DATA_TYPE_DATA_UNCACHE, address, size);

new_uncache:
	/* get a cache address for the new uncache mapping */
	uncache_addr = _cache_new_udata(elem, core, func, line, CACHE_DATA_TYPE_DATA_CACHE, size);
	if (!uncache_addr)
		return uncache_addr;

found_uncache:
	return uncache_addr;
}
#define cache_to_uncache(address) \
	_cache_to_uncache(address, __func__, __LINE__, sizeof(*address))

static inline int _is_uncache(void *address, const char *func, int line,
		size_t size)
{
	struct cache_elem *elem;
	int i;

	fprintf(stdout, "\n\n");

	/* find elem with uncache address */
	for (i = 0; i < HOST_CACHE_ELEMS; i++) {
		elem = &host_cache->elem[i];
		if (elem->uncache == address) {
			fprintf(stdout, "is uncache found: %s() line %d\n", func, line);
			return 1;
		}
	}

	fprintf(stdout, "is uncache not found: %s() line %d\n", func, line);
	return 0;
}

/* check for memory type - not foolproof here */
#define is_uncached(address)	\
	_is_uncache(address, __func__, __LINE__, sizeof(*address))

#define platform_shared_get(ptr, bytes) 			\
	({dcache_invalidate_region(ptr, bytes);			\
	_cache_to_uncache(ptr, __func__, __LINE__, sizeof(*ptr));}) 		\


void platform_init_memmap(struct sof *sof);

#define platform_rfree_prepare(ptr) \
	({fprintf(stdout, "prepare free %s() line %d size\n", __func__, __LINE__, sizeof(*ptr)); \
	ptr;})



// wb will copy cache[core] bytes to uncache in 64byte chunks

// wb inv copy cache[core] bytes to uncache in 64 byte chunks and also to other cache

// alloc will alloc uncache and cache

#define ARCH_OOPS_SIZE	0

static inline void *arch_get_stack_entry(void)
{
	return NULL;
}

static inline uint32_t arch_get_stack_size(void)
{
	return 0;
}

/* NOTE - FAKE Memory configurations are used by UT's to test allocator */

#define SRAM_BANK_SIZE	0x10000
#define LP_SRAM_SIZE SRAM_BANK_SIZE
#define HP_SRAM_SIZE SRAM_BANK_SIZE

#define HP_SRAM_BASE	0
#define LP_SRAM_BASE	0

/* Heap section sizes for system runtime heap for primary core */
#define HEAP_SYS_RT_0_COUNT64		128
#define HEAP_SYS_RT_0_COUNT512		16
#define HEAP_SYS_RT_0_COUNT1024		4

/* Heap section sizes for system runtime heap for secondary core */
#define HEAP_SYS_RT_X_COUNT64		64
#define HEAP_SYS_RT_X_COUNT512		8
#define HEAP_SYS_RT_X_COUNT1024		4

/* Heap section sizes for module pool */
#define HEAP_RT_COUNT64		128
#define HEAP_RT_COUNT128	64
#define HEAP_RT_COUNT256	128
#define HEAP_RT_COUNT512	8
#define HEAP_RT_COUNT1024	4
#define HEAP_RT_COUNT2048	1
#define HEAP_RT_COUNT4096	1

/* Heap configuration */
#define HEAP_RUNTIME_SIZE \
	(HEAP_RT_COUNT64 * 64 + HEAP_RT_COUNT128 * 128 + \
	HEAP_RT_COUNT256 * 256 + HEAP_RT_COUNT512 * 512 + \
	HEAP_RT_COUNT1024 * 1024 + HEAP_RT_COUNT2048 * 2048 + \
	HEAP_RT_COUNT4096 * 4096)

/* Heap section sizes for runtime shared heap */
#define HEAP_RUNTIME_SHARED_COUNT64	(64 + 32 * CONFIG_CORE_COUNT)
#define HEAP_RUNTIME_SHARED_COUNT128	64
#define HEAP_RUNTIME_SHARED_COUNT256	4
#define HEAP_RUNTIME_SHARED_COUNT512	16
#define HEAP_RUNTIME_SHARED_COUNT1024	4

#define HEAP_RUNTIME_SHARED_SIZE \
	(HEAP_RUNTIME_SHARED_COUNT64 * 64 + HEAP_RUNTIME_SHARED_COUNT128 * 128 + \
	HEAP_RUNTIME_SHARED_COUNT256 * 256 + HEAP_RUNTIME_SHARED_COUNT512 * 512 + \
	HEAP_RUNTIME_SHARED_COUNT1024 * 1024)

/* Heap section sizes for system shared heap */
#define HEAP_SYSTEM_SHARED_SIZE		0x1500

#define HEAP_BUFFER_BLOCK_SIZE		0x100
#define HEAP_BUFFER_COUNT	(HEAP_BUFFER_SIZE / HEAP_BUFFER_BLOCK_SIZE)

#define HEAP_SYSTEM_M_SIZE		0x8000 /* heap primary core size */
#define HEAP_SYSTEM_S_SIZE		0x6000 /* heap secondary core size */

#define HEAP_SYSTEM_T_SIZE \
	(HEAP_SYSTEM_M_SIZE + ((CONFIG_CORE_COUNT - 1) * HEAP_SYSTEM_S_SIZE))

#define HEAP_SYS_RUNTIME_M_SIZE \
	(HEAP_SYS_RT_0_COUNT64 * 64 + HEAP_SYS_RT_0_COUNT512 * 512 + \
	HEAP_SYS_RT_0_COUNT1024 * 1024)

#define HEAP_SYS_RUNTIME_S_SIZE \
	(HEAP_SYS_RT_X_COUNT64 * 64 + HEAP_SYS_RT_X_COUNT512 * 512 + \
	HEAP_SYS_RT_X_COUNT1024 * 1024)

#define HEAP_SYS_RUNTIME_T_SIZE \
	(HEAP_SYS_RUNTIME_M_SIZE + ((CONFIG_CORE_COUNT - 1) * \
	HEAP_SYS_RUNTIME_S_SIZE))

/* Heap section sizes for module pool */
#define HEAP_RT_LP_COUNT8			0
#define HEAP_RT_LP_COUNT16			256
#define HEAP_RT_LP_COUNT32			128
#define HEAP_RT_LP_COUNT64			64
#define HEAP_RT_LP_COUNT128			64
#define HEAP_RT_LP_COUNT256			96
#define HEAP_RT_LP_COUNT512			8
#define HEAP_RT_LP_COUNT1024			4

/* Heap configuration */
#define SOF_LP_DATA_SIZE			0x4000

#define HEAP_LP_SYSTEM_BASE		(LP_SRAM_BASE + SOF_LP_DATA_SIZE)
#define HEAP_LP_SYSTEM_SIZE		0x1000

#define HEAP_LP_RUNTIME_BASE \
	(HEAP_LP_SYSTEM_BASE + HEAP_LP_SYSTEM_SIZE)
#define HEAP_LP_RUNTIME_SIZE \
	(HEAP_RT_LP_COUNT8 * 8 + HEAP_RT_LP_COUNT16 * 16 + \
	HEAP_RT_LP_COUNT32 * 32 + HEAP_RT_LP_COUNT64 * 64 + \
	HEAP_RT_LP_COUNT128 * 128 + HEAP_RT_LP_COUNT256 * 256 + \
	HEAP_RT_LP_COUNT512 * 512 + HEAP_RT_LP_COUNT1024 * 1024)

#define HEAP_LP_BUFFER_BLOCK_SIZE		0x180
#define HEAP_LP_BUFFER_COUNT \
	(HEAP_LP_BUFFER_SIZE / HEAP_LP_BUFFER_BLOCK_SIZE)

#define HEAP_LP_BUFFER_BASE LP_SRAM_BASE
#define HEAP_LP_BUFFER_SIZE LP_SRAM_SIZE

/* SOF Core S configuration */
#define SOF_CORE_S_SIZE \
	ALIGN((HEAP_SYSTEM_S_SIZE + HEAP_SYS_RUNTIME_S_SIZE + SOF_STACK_SIZE),\
	SRAM_BANK_SIZE)
#define SOF_CORE_S_T_SIZE ((CONFIG_CORE_COUNT - 1) * SOF_CORE_S_SIZE)

#endif /* __PLATFORM_LIB_MEMORY_H__ */

#else

#error "This file shouldn't be included from outside of sof/lib/memory.h"

#endif /* __SOF_LIB_MEMORY_H__ */
