#include "server.h"
#include "logger.h"

static int make_socket_non_blocking(int sfd)
{
    int flags, r;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
        goto error;

    flags |= O_NONBLOCK;
    r = fcntl(sfd, F_SETFL, flags);
    if (r == -1)
        goto error;

    return 0;

error:
    r = errno;
    log_error("fcntl\n");
    return r;
}

static int server_init(struct server *srv, const char *addr, int port, const char *data_path)
{
    int r;

    memset(srv, 0, sizeof(*srv));
    rwlock_init(&srv->lock);

    http_stat_init(&srv->stats);

    r = db_init(&srv->db);
    if (r)
        return r;

    r = db_load_data(&srv->db, data_path);
    if (r)
        goto free_db;

    srv->addr = addr;
    srv->port = port;

    return 0;

free_db:
    db_free(&srv->db);

    return r;
}

static int server_thread_bind(struct server_thread *thread)
{
    struct sockaddr_in addr;
    int r, sfd, val;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(thread->srv->addr);
    addr.sin_port = htons(thread->srv->port);

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        r = errno;
        log_error("could not socket, error %d\n", r);
        return r;
    }

    val = 1;
    r = setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    if (r == -1) {
        log_error("cant set reuseport accept\n");
        r = errno;
        goto fail;
    }

    val = 1;
    if (setsockopt(sfd, SOL_TCP, TCP_QUICKACK, &val, sizeof(val))) {
        r = errno;
        log_error("cant set tcp quick ack\n");
        goto fail;
    }


    val = 1;
    if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &val, sizeof(val))) {
        r = errno;
        log_error("cant set tcp no delay\n");
        goto fail;
    }
/*
    val = 1;
    r = setsockopt(sfd, SOL_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val));
    if (r == -1) {
        r = errno;
        log_error("cant set defer accept\n");
        goto fail;
    }
*/
    r = bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    if (r == -1) {
        r = errno;
        log_error("could not bind, error %d\n", r);
        goto fail;
    }

    r = make_socket_non_blocking(sfd);
    if (r != 0) {
        log_error("could not make socket non blocking, error %d\n", r);
        goto fail;
    }

    thread->sfd = sfd;
    return 0;

fail:
    close(sfd);
    return r;
}

static int server_thread_insert_connection(struct server_thread *thread, struct connection *new_conn)
{
    struct connection *conn;
    int i;

    if (new_conn->fd < ARRAY_SIZE(thread->conn_table)) {

        if (thread->conn_table[new_conn->fd])
            return EEXIST;

        thread->conn_table[new_conn->fd] = new_conn;
        get_connection(new_conn);
        thread->num_conns++;
        {
            int num_conns = thread->num_conns;
            if (num_conns > thread->max_num_conns) {
                thread->max_num_conns = num_conns;
            }
        }
        log_debug("insert connection 0x%p\n", new_conn);
        return 0;
    }

    i = hash_int(new_conn->fd) % ARRAY_SIZE(thread->conn_list);
    list_for_each_entry(conn, &thread->conn_list[i], list) {
        if (conn->fd == new_conn->fd)
            return EEXIST;

        bug_on(conn == new_conn);
    }

    get_connection(new_conn);
    list_add_tail(&new_conn->list, &thread->conn_list[i]);
    thread->num_conns++;
    {
        int num_conns = thread->num_conns;
        if (num_conns > thread->max_num_conns) {
            thread->max_num_conns = num_conns;
        }
    }
    log_debug("insert connection 0x%p\n", new_conn);

    return 0;
}

static int server_thread_remove_connection(struct server_thread *thread, struct connection *conn)
{
    int removed = 0;
    struct connection *ex_conn;

    log_debug("remove connection 0x%p\n", conn);

    if (conn->fd < ARRAY_SIZE(thread->conn_table)) {
        ex_conn = thread->conn_table[conn->fd];
        if (ex_conn) {
            bug_on(ex_conn != conn);
            thread->conn_table[conn->fd] = NULL;
            thread->num_conns--;
            put_connection(conn);
            return 1;
        }
        return 0;
    }

    if (!list_empty(&conn->list)) {
        list_del_init(&conn->list);
        thread->num_conns--;
        removed = 1;
    }

    if (removed)
        put_connection(conn);

    return removed;
}

static struct connection *server_thread_lookup_connection(struct server_thread *thread, int fd)
{
    struct connection *conn;
    int i;

    if (fd < ARRAY_SIZE(thread->conn_table)) {
        conn = thread->conn_table[fd];
        if (conn) {
            get_connection(conn);
            return conn;
        }
    }

    i = hash_int(fd) % ARRAY_SIZE(thread->conn_list);

    list_for_each_entry(conn, &thread->conn_list[i], list) {
        if (conn->fd == fd) {
            thread->conn_table_misses++;
            get_connection(conn);
            return conn;
        }
    }

    return NULL;
}

static int server_thread_listen(struct server_thread *thread)
{
    struct epoll_event event;
    int r, efd;

    r = listen(thread->sfd, SOMAXCONN);
    if (r == -1) {
        r = errno;
        log_error("listen %d\n", r);
        return r;
    }

    efd = epoll_create1(0);
    if (efd == -1) {
        r = errno;
        log_error("epoll_create %d\n", r);
        return r;
    }

    memset(&event, 0, sizeof(event));
    event.data.fd = thread->sfd;
    event.events = EPOLLIN | EPOLLET;
    r = epoll_ctl (efd, EPOLL_CTL_ADD, thread->sfd, &event);
    if (r == -1) {
        r = errno;
        log_error("epoll_ctl %d\n", r);
        return r;
    }

    thread->efd = efd;
    return 0;
}

static int server_handle_new_connection(struct server_thread *thread)
{
    struct connection *conn;
    struct sockaddr in_addr;
    socklen_t in_len;
    int infd;
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    struct epoll_event new_event;
    int r, val;

    log_debug("accepting\n");
    in_len = sizeof in_addr;
    infd = accept(thread->sfd, &in_addr, &in_len);
    if (infd == -1) {
        if ((errno == EAGAIN) ||
            (errno == EWOULDBLOCK)) {
            /* We have processed all incoming connections. */
            log_debug("no more incoming connections\n");
            return EAGAIN;
        } else {
            log_error("accept %d\n", errno);
            return errno;
        }
    }

    r = getnameinfo(&in_addr, in_len,
                    hbuf, sizeof hbuf,
                    sbuf, sizeof sbuf,
                    NI_NUMERICHOST | NI_NUMERICSERV);
    if (r == 0)
    {
        log_debug("accepted connection on descriptor %d "
                "(host=%s, port=%s)\n", infd, hbuf, sbuf);
    }

    /* Make the incoming socket non-blocking and add it to the
        list of fds to monitor. */
    r = make_socket_non_blocking(infd);
    if (r != 0)
    {
        log_error("can't make non blocking socket r %d\n", r);
        close(infd);
        return r;
    }

    val = 1;
    if (setsockopt(infd, SOL_TCP, TCP_NODELAY, &val, sizeof(val))) {
        r = errno;
        log_error("cant set tcp no delay\n");
        close(infd);
        return r;
    }

    val = 1;
    if (setsockopt(infd, SOL_TCP, TCP_QUICKACK, &val, sizeof(val))) {
        r = errno;
        log_error("cant set tcp quick ack\n");
        close(infd);
        return r;
    }

    conn = new_connection(infd, thread);
    if (!conn) {
        r = ENOMEM;
        log_debug("can't make new connection\n");
        close(infd);
        return r;
    }

    r = server_thread_insert_connection(thread, conn);
    if (r) {
        log_debug("can't insert new connection\n");
        put_connection(conn);
        return r;
    }

    memset(&new_event, 0, sizeof(new_event));
    new_event.data.fd = infd;
    new_event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    r = epoll_ctl (thread->efd, EPOLL_CTL_ADD, infd, &new_event);
    if (r == -1)
    {
        r = errno;
        log_error("epoll_ctl %d\n", r);
        if (server_thread_remove_connection(thread, conn))
            put_connection(conn);
        return r;
    }

    return 0;
}

static int server_handle_fd_error(struct server_thread *thread, int fd)
{
    struct connection *conn;

    conn = server_thread_lookup_connection(thread, fd);
    if (!conn) {
        //log_error("can't find connection by fd %d", fd);
        close(fd);
        return EINVAL;
    }

    if (server_thread_remove_connection(thread, conn)) {
        close_connection(conn);
        put_connection(conn);
    }
    put_connection(conn);

    return 0;
}

static int server_handle_pollin(struct server_thread *thread, int fd)
{
    struct connection *conn;
    int r, close;

    conn = server_thread_lookup_connection(thread, fd);
    if (!conn) {
        //log_error("can't find connection by fd %d\n", fd);
        return EINVAL;
    }

    r = connection_on_read(conn, &close);
    if (close) {
        if (server_thread_remove_connection(thread, conn)) {
            close_connection(conn);
            put_connection(conn);
        }
    }
    put_connection(conn);
    return r;
}

static int server_handle_pollout(struct server_thread *thread, int fd)
{
    struct connection *conn;
    int r, close;

    conn = server_thread_lookup_connection(thread, fd);
    if (!conn) {
        //log_error("can't find connection by fd %d\n", fd);
        return EINVAL;
    }

    r = connection_on_write(conn, &close);
    if (close) {
        if (server_thread_remove_connection(thread, conn)) {
            close_connection(conn);
            put_connection(conn);
        }
    }
    put_connection(conn);
    return r;
}

static int server_handle_event(struct server_thread *thread, struct epoll_event *event)
{
    int r;
    int fd;

    if (thread->thread.stopping)
        return 0;

    log_debug("event 0x%x\n", event->events);

    atomic_inc(&thread->num_events);

    fd = event->data.fd;
    if ((event->events & EPOLLERR) ||
            (event->events & EPOLLHUP) ||
            (!(event->events & EPOLLIN) && !(event->events & EPOLLOUT))) {
            /* An error has occured on this fd, or the socket is not
                ready for reading (why were we notified then?) */
        server_handle_fd_error(thread, fd);
        return 0;
    }
    
    if (thread->sfd == fd) {
        /* We have a notification on the listening socket, which
            means one or more incoming connections. */
        while (!thread->thread.stopping) {
            r = server_handle_new_connection(thread);
            if (r == EAGAIN)
                return 0;
        }
    }

    if (thread->thread.stopping)
        return 0;

    if (event->events & EPOLLIN) {
        server_handle_pollin(thread, fd);
    }

    if (event->events & EPOLLOUT) {
        server_handle_pollout(thread, fd);
    }

    if (event->events & EPOLLIN || event->events & EPOLLOUT)
        return 0;

    log_error("unknown epoll event 0x%x", event->events);
    return 0;
}

static int server_event_loop(struct server_thread *thread)
{
    int r;

    r = 0;
    /* The event loop */
    while (!thread->thread.stopping)
    {
        int n, i;

        n = epoll_wait(thread->efd, thread->events, ARRAY_SIZE(thread->events), -1);
        if (n < 0) {
            r = errno;
            log_error("epoll_wait error %d, efd %d\n", r, thread->efd);
            if (r == EINTR && !thread->thread.stopping)
                continue;

            goto out;
        }

        if (n > thread->max_events)
            thread->max_events = n;

        log_debug("has %d events\n", n);

        for (i = 0; i < n; i++) {
            r = server_handle_event(thread, &thread->events[i]);
            if (r != 0) {
                log_error("handle event error %d\n", r);
                goto out;
            }
        }
    }

out:

    log_info("stopped, num_events %d, max_events %d r %d\n",
        atomic_read(&thread->num_events), thread->max_events, r);

    return r;
}

static struct server g_srv;

struct server* get_server(void)
{
    return &g_srv;
}

static void* server_thread_routine(void *ctx)
{
    struct server_thread *thread = ctx;
    int r;

    r = server_thread_bind(thread);
    if (r)
        return NULL;

    r = server_thread_listen(thread);
    if (r) {
        close(thread->sfd);
        thread->sfd = -1;
        return NULL;
    }

    server_event_loop(thread);

    log_info("close sfd %d efd %d\n", thread->sfd, thread->efd);

    close(thread->sfd);
    thread->sfd = -1;
    close(thread->efd);
    thread->efd = -1;

    return NULL;
}

static void server_thread_deinit(struct server_thread *thread)
{
    struct connection *conn, *tmp;
    int i;

    for (i = 0; i < ARRAY_SIZE(thread->conn_table); i++) {
        conn = thread->conn_table[i];
        if (conn) {
            close_connection(conn);
            put_connection(conn);
            put_connection(conn);
        }
    }

    for (i = 0; i < ARRAY_SIZE(thread->conn_list); i++) {
        list_for_each_entry_safe(conn, tmp, &thread->conn_list[i], list) {
            list_del_init(&conn->list);
            close_connection(conn);
            put_connection(conn);
            put_connection(conn);
        }
    }

    memory_pool_deinit(&thread->conn_pool);

    if (thread->sfd >= 0)
        close(thread->sfd);

    if (thread->efd >= 0)
        close(thread->efd);

    log_info("max_num_conns %d\n", thread->max_num_conns);
    log_info("conn_table_misses %lld\n", thread->conn_table_misses);
}

static int server_thread_init(struct server_thread *thread)
{
    size_t i;
    int r;

    memset(thread, 0, sizeof(*thread));

    for (i = 0; i < ARRAY_SIZE(thread->conn_list); i++)
    {
        list_init(&thread->conn_list[i]);
    }

    memset(&thread->conn_table, 0, sizeof(thread->conn_table));

    r = memory_pool_init(&thread->conn_pool, sizeof(struct connection), 1000);
    if (r)
        return r;

    http_stat_init(&thread->stats);
    thread->sfd = thread->efd = -1;

    return 0;
}

static int server_start_threads(struct server *srv, int num_threads)
{
    int r;
    int i;
    struct server_thread *thread;

    if (num_threads > ARRAY_SIZE(srv->threads))
        return -1;

    for (i = 0; i < num_threads; i++) {
        thread = &srv->threads[i];
        r = server_thread_init(thread);
        if (r) {
            int j;

            for (j = 0; j < i; j++) {
                thread = &srv->threads[j];
                server_thread_deinit(thread);
            }
        }
    }

    for (i = 0; i < num_threads; i++) {
        thread = &srv->threads[i];
        thread->srv = srv;
        r = thread_create(&thread->thread, i, server_thread_routine, thread);
        if (r) {
            int j;

            for (j = 0; j < i; j++) {
                thread = &srv->threads[j];
                thread_stop(&thread->thread);
                thread_join(&thread->thread);
                server_thread_deinit(thread);
            }
            return r;
        }
    }

    srv->num_threads = num_threads;
    return 0;
}

#ifdef __STATS__
static void server_stat_dump(struct server *srv)
{
    int i;

    http_stat_init(&srv->stats);
    for (i = 0; i < srv->num_threads; i++)
        http_stat_merge(&srv->stats, &srv->threads[i].stats);

    http_stat_dump(&srv->stats);
}
#endif

static int server_main_loop(struct server *srv)
{
    while (1) {
#ifdef __STATS__
        if (sleep(10)) {
#else
        if (sleep(3600)) {
#endif
            log_error("sleep interrupted\n");
            break;
        }

#ifdef __STATS__
        server_stat_dump(srv);
#endif

    }

    return 0;
}

static int server_shutdown(struct server *srv)
{
    struct server_thread *thread;
    int i;

    if (0 != atomic_cmpxchg(&srv->stopping, 0, 1))
        return -1;

    rwlock_lock(&srv->lock);

    log_info("shutting down\n");

    for (i = 0; i < srv->num_threads; i++) {
        thread = &srv->threads[i];
        thread_stop(&thread->thread);
    }

    for (i = 0; i < srv->num_threads; i++) {
        thread = &srv->threads[i];
        thread_kill(&thread->thread);
    }

    for (i = 0; i < srv->num_threads; i++) {
        thread = &srv->threads[i];
        thread_join(&thread->thread);
    }

    for (i = 0; i < srv->num_threads; i++) {
        thread = &srv->threads[i];
        server_thread_deinit(thread);
    }

#ifdef __STATS__
    server_stat_dump(srv);
#endif

    srv->num_threads = 0;

    db_free(&srv->db);

    log_info("shutdown complete\n");

    rwlock_unlock(&srv->lock);

    return 0;
}

static void server_term(int signum)
{
    int r;

    log_info("received signal %d\n", signum);
    
    r = server_shutdown(get_server());
    if (r == 0) {
        log_flush();
        exit(0);
    }
}

int server_run(struct server *srv, const char *addr, int port, int num_threads, const char *data_path)
{
    int r;

    log_info("run at addr %s port %d threads %d data_path %s\n",
        addr, port, num_threads, data_path);

    if (!addr || port <= 0 || num_threads <= 0 || !data_path)
        return EINVAL;

    memset(&srv->sig_term_action, 0, sizeof(srv->sig_term_action));
    srv->sig_term_action.sa_handler = server_term;
    sigaction(SIGTERM, &srv->sig_term_action, NULL);

    memset(&srv->sig_int_action, 0, sizeof(srv->sig_int_action));
    srv->sig_int_action.sa_handler = server_term;
    sigaction(SIGINT, &srv->sig_int_action, NULL);

    signal(SIGPIPE, SIG_IGN);

    r = server_init(srv, addr, port, data_path);
    if (r)
        return r;

    r = server_start_threads(srv, num_threads);
    if (r != 0)
        goto fail;

    r = server_main_loop(srv);
    server_shutdown(srv);
    return r;

fail:
    server_shutdown(srv);
    return r;
}