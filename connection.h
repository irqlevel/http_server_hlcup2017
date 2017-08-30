#pragma once

#include "base.h"
#include "rwlock.h"
#include "list.h"
#include "http.h"
#include "memory_pool.h"

struct server_thread;

struct connection {
    struct list_head list;
    long users;
    int fd;
    struct http_request request;
    struct http_response response;
    struct server_thread *thread;
};

struct connection *new_connection(int fd, struct server_thread *threasd);

void close_connection(struct connection *conn);

void get_connection(struct connection *conn);
void put_connection(struct connection *conn);

int connection_on_read(struct connection *conn, int *close);
int connection_on_write(struct connection *conn, int *close);
