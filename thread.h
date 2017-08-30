#pragma once

#include "base.h"

struct thread {
    pthread_t thread;
    void *(*func)(void *ctx);
    void *ctx;
    int stopping;
    int cpu;
};

int thread_create(struct thread *thread, int cpu, void *(*func)(void *ctx), void *ctx);

void thread_stop(struct thread *thread);

void thread_kill(struct thread *thread);

void thread_join(struct thread *thread);

void thread_free(struct thread *thread);