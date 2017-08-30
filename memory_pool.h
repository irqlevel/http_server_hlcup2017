#pragma once


#include "base.h"
#include "list.h"
#include "rwlock.h"

struct memory_pool {
    struct rwlock lock;
    struct list_head list;
    size_t size;
};

int memory_pool_init(struct memory_pool *pool, size_t size, size_t nr_preallocs);

void* memory_pool_alloc(struct memory_pool *pool);

void memory_pool_free(struct memory_pool *pool, void *addr);

void memory_pool_deinit(struct memory_pool *pool);