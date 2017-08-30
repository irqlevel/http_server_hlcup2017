#include "memory_pool.h"

int memory_pool_init(struct memory_pool *pool, size_t size, size_t nr_preallocs)
{
    struct list_head *entry, *tmp;
    size_t i;
    int r;

    if (size < sizeof(*entry))
        return EINVAL;

    rwlock_init(&pool->lock);
    list_init(&pool->list);
    pool->size = size;

    for (i = 0; i < nr_preallocs; i++) {
        entry = malloc(size);
        if (!entry) {
            r = ENOMEM;
            goto fail;
        }
        list_add_tail(entry, &pool->list);
    }

    return 0;

fail:
    list_for_each_safe(entry, tmp, &pool->list) {
        free(entry);
    }

    return r;
}

void* memory_pool_alloc(struct memory_pool *pool)
{
    struct list_head *entry;

    if (!list_empty(&pool->list)) {
        rwlock_lock(&pool->lock);
        if (!list_empty(&pool->list)) {
            entry = pool->list.next;
            list_del_init(entry);
            rwlock_unlock(&pool->lock);
            return entry;
        }
        rwlock_unlock(&pool->lock);
    }

    return malloc(pool->size);
}

void memory_pool_free(struct memory_pool *pool, void *addr)
{

    struct list_head *entry = addr;

    rwlock_lock(&pool->lock);
    list_add_tail(entry, &pool->list);
    rwlock_unlock(&pool->lock);
}

void memory_pool_deinit(struct memory_pool *pool)
{
    struct list_head *entry, *tmp;

    list_for_each_safe(entry, tmp, &pool->list) {
        free(entry);
    }
}