#include "connection.h"
#include "logger.h"
#include "server.h"

struct connection *new_connection(int fd, struct server_thread *thread)
{
    struct connection *conn;

    bug_on(fd < 0);

    conn = memory_pool_alloc(&thread->conn_pool);
    if (!conn)
        return NULL;

    list_init(&conn->list);
    conn->fd = fd;
    conn->users = 1;
    conn->thread = thread;

    http_request_init(&conn->request);
    http_response_init(&conn->response);

    log_debug("new connection 0x%p %d\n", conn, fd);
    return conn;
}

static void __close_connection(struct connection *conn)
{
    if (conn->fd >= 0) {
        log_debug("close connection 0x%p %d\n", conn, conn->fd);

        close(conn->fd);
        conn->fd = -1;
    }
}

void close_connection(struct connection *conn)
{
    __close_connection(conn);
}

static void free_connection(struct connection *conn)
{
    log_debug("free_connection 0x%p\n", conn);

    bug_on(!list_empty(&conn->list));
    bug_on(conn->users);

    close_connection(conn);

    http_request_reset(&conn->request);
    http_response_reset(&conn->response);

    bug_on(conn->fd >= 0);
    memory_pool_free(&conn->thread->conn_pool, conn);
}

void get_connection(struct connection *conn)
{
    conn->users++;
}

void put_connection(struct connection *conn)
{
    bug_on(!conn->users);
    conn->users--;
    if (!conn->users)
        free_connection(conn);
}

int connection_on_read(struct connection *conn, int *close)
{
    int r;

    *close = 0;
    if (conn->fd < 0) {
        r = EINVAL;
        goto out;
    }

    while (conn->request.state == HTTP_STATE_READING) {
        r = http_request_read(&conn->request, conn->fd, close);
        if (*close)
            break;

        if (r)
            break;
    }

    if (conn->request.state == HTTP_STATE_READ_COMPLETE) {
        r = http_handler(&conn->request, &conn->response, close);
        if (r)
            goto out;
        
        while (conn->response.state == HTTP_STATE_WRITING) {
            r = http_response_write(&conn->response, conn->fd, close);
            if (*close)
                goto out;

            if (r)
                goto out;
        }

        if (conn->response.state == HTTP_STATE_WRITE_COMPLETE) {
            if (strncmp(conn->request.connection, "close", strlen("close") + 1) == 0) {
                *close = 1;
            }

            http_stat_request(&conn->thread->stats, &conn->request, &conn->response);
            http_request_reset(&conn->request);
            http_response_reset(&conn->response);
        }
    }

out:
    return r;
}

int connection_on_write(struct connection *conn, int *close)
{
    int r;

    *close = 0;
    r = 0;

    if (conn->fd < 0) {
        r = EINVAL;
        goto out;
    }

    while (conn->response.state == HTTP_STATE_WRITING) {
        r = http_response_write(&conn->response, conn->fd, close);
        if (*close)
            break;

        if (r)
            break;
    }

    if (conn->response.state == HTTP_STATE_WRITE_COMPLETE) {
        if (strncmp(conn->request.connection, "close", strlen("close") + 1) == 0) {
            *close = 1;
        }
#ifdef __STATS__
        http_stat_request(&conn->thread->stats, &conn->request, &conn->response);
#endif
        http_request_reset(&conn->request);
        http_response_reset(&conn->response);
    }

out:
    return r;
}
