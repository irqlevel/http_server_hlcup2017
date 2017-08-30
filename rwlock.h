#pragma once

#include "base.h"

struct rwlock {
    pthread_rwlock_t lock;
};

void rwlock_init(struct rwlock *lock);
void rwlock_lock(struct rwlock *lock);
void rwlock_unlock(struct rwlock *lock);
void rwlock_read_lock(struct rwlock *lock);
void rwlock_read_unlock(struct rwlock *lock);
void rwlock_deinit(struct rwlock *lock);