#pragma once

#include "base.h"

#include "list.h"
#include "thread.h"
#include "rwlock.h"
#include "connection.h"
#include "atomic.h"
#include "db.h"
#include "memory_pool.h"
#include "http.h"

struct server;

#define MAX_EVENTS 64000
#define MAX_THREADS 32

#define CONN_LIST_SIZE 2048
#define CONN_TABLE_SIZE 10000

struct server_thread {
    struct server *srv;
    struct epoll_event events[MAX_EVENTS];
    struct thread thread;

    struct list_head conn_list[CONN_LIST_SIZE];
    struct connection *conn_table[CONN_TABLE_SIZE];

    int64_t conn_table_misses;

    struct memory_pool conn_pool;

    struct http_stat stats;

    int num_conns;
    int max_num_conns;

    int num_events;
    int max_events;
    int sfd;
    int efd;
};

struct server {
    struct server_thread threads[MAX_THREADS];
    struct rwlock lock;

    struct db db;

    struct sigaction sig_term_action;
    struct sigaction sig_int_action;

    struct http_stat stats;

    const char *addr;
    int port;

    int num_threads;
    int stopping;
};

int server_run(struct server *srv, const char *addr, int port, int num_threads, const char *data_path);

struct server* get_server(void);