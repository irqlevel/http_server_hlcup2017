#include "rwlock.h"

void rwlock_init(struct rwlock *lock)
{
    int r;

    r = pthread_rwlock_init(&lock->lock, NULL);
    bug_on(r);
}

void rwlock_lock(struct rwlock *lock)
{
    int r;

    r = pthread_rwlock_wrlock(&lock->lock);
    bug_on(r);
}

void rwlock_unlock(struct rwlock *lock)
{
    int r;

    r = pthread_rwlock_unlock(&lock->lock);
    bug_on(r);
}

void rwlock_read_lock(struct rwlock *lock)
{
    int r;

    r = pthread_rwlock_rdlock(&lock->lock);
    bug_on(r);
}

void rwlock_read_unlock(struct rwlock *lock)
{
    int r;

    r = pthread_rwlock_unlock(&lock->lock);
    bug_on(r);
}

void rwlock_deinit(struct rwlock *lock)
{
    int r;
    
    r = pthread_rwlock_destroy(&lock->lock);
    bug_on(r);
}