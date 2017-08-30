#include "thread.h"
#include "logger.h"

static void* thread_routine(void *ctx)
{
    struct thread *thread = ctx;
/*
    cpu_set_t cpuset;
    int r;

    CPU_ZERO(&cpuset);
    CPU_SET(thread->cpu, &cpuset);

    r = pthread_setaffinity_np(thread->thread, sizeof(cpuset), &cpuset);
    if (r != 0) {
        log_error("can't setup cpu affinity %d\n", r);
    }

    sleep(0);
*/
    return thread->func(thread->ctx);
}

int thread_create(struct thread *thread, int cpu, void *(*func)(void *ctx), void *ctx)
{
    int r;

    memset(thread, 0, sizeof(*thread));

    thread->cpu = cpu;
    thread->func = func;
    thread->ctx = ctx;

    r = pthread_create(&thread->thread, NULL, thread_routine, thread);
    if (r)
        return r;

    return 0;
}

void thread_join(struct thread *thread)
{
    int r;

    r = pthread_join(thread->thread, NULL);
    bug_on(r);
}

void thread_kill(struct thread *thread)
{
    pthread_kill(thread->thread, SIGTERM);
}

void thread_free(struct thread *thread)
{
    memset(thread, 0, sizeof(*thread));
}

void thread_stop(struct thread *thread)
{
    thread->stopping = 1;
}