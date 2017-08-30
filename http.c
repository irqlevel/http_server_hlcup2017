#include "http.h"
#include "logger.h"
#include "handlers.h"

static void time_point_capture(struct time_point *point)
{
#ifdef __STATS__
    if (!point->valid) {
        gettimeofday(&point->value, NULL);
        point->valid = 1;
    }
#endif
}

static void time_point_reset(struct time_point *point)
{
    point->valid = 0;
}

static uint64_t time_point_sub(struct time_point *a, struct time_point *b)
{
    struct timeval result;

    if (!a->valid || !b->valid)
        return 0;

    if (timercmp(&a->value, &b->value, <=))
        return 0;

    timersub(&a->value, &b->value, &result);

    return 1000000 * result.tv_sec + result.tv_usec;
}

void http_request_init(struct http_request *request)
{
    request->read = 0;
    request->header_size = 0;
    request->body_size = 0;
    request->method_len = 0;
    request->path_len = 0;
    request->method_code = 0;
    request->state = HTTP_STATE_READING;
    request->method[0] = '\0';
    request->path[0] = '\0';
    request->agent[0] = '\0';
    request->host[0] = '\0';
    request->accept[0] = '\0';
    request->connection[0] = '\0';
    request->content_length[0] = '\0';
    request->index = REQ_INDEX_INVALID;

    time_point_reset(&request->read_start);
    time_point_reset(&request->read_finish);
    time_point_reset(&request->handler_start);
    time_point_reset(&request->handler_finish);
}

void http_response_init(struct http_response *response)
{
    response->header_size = 0;
    response->body_size = 0;
    response->sent = 0;
    response->state = HTTP_STATE_INITED;
    response->status_code = 0;
    response->close = 0;
    response->body = NULL;

    strncpy(response->connection, "keep-alive", sizeof("keep-alive"));
    strncpy(response->content_type, "application/json; charset=utf-8", sizeof("application/json; charset=utf-8"));

    time_point_reset(&response->write_start);
    time_point_reset(&response->write_finish);
}

void http_request_reset(struct http_request *request)
{
    http_request_init(request);
}

void http_response_reset(struct http_response *response)
{
    if (response->body && response->body != response->body_buf)
        free(response->body);

    http_response_init(response);
}

static int http_get_header_value(struct phr_header *header,
        const char *key_name, char *value, size_t value_size)
{
    if (0 == strncmp(key_name, header->name, header->name_len))
    {
        if (header->name_len != strlen(key_name))
        {
            log_error("invalid header key len %d %d\n", header->name_len, key_name);
            return EINVAL;
        }

        if (header->value_len >= value_size)
        {
            log_error("invalid header value len %d %d %.*s %.*s\n",
                header->value_len, value_size, header->name_len, header->name,
                header->value_len, header->value);
            return EINVAL;
        }

        memcpy(value, header->value, header->value_len);
        value[header->value_len] = '\0';
        return 0;
    }

    return EAGAIN;
}

static int http_request_parse(struct http_request *request, int *close)
{
    int r, header_size;
    const char *method, *path;
    size_t i, num_headers, method_len, path_len;
    int minor_version;
    struct phr_header headers[16];

    time_point_capture(&request->read_finish);

    /* returns number of bytes consumed if successful, -2 if request is partial,
    * -1 if failed */
    num_headers = ARRAY_SIZE(headers);
    header_size = phr_parse_request(request->buf, request->read, &method, &method_len, &path,
                        &path_len, &minor_version, headers, &num_headers,
                        0);

    log_debug("parse %d bytes header_size %d num_headers %d\n", request->read, header_size, num_headers);

    switch (header_size) {
    case -2:
        time_point_reset(&request->read_finish);
        return 0;
    case -1:
        log_error("can't parse headers\n");
        r = EINVAL;
        goto fail;
    }

    log_debug("parse path %.*s method %.*s\n", path_len, path, method_len, method);

    request->header_size = header_size;

    if (method_len >= sizeof(request->method)) {
        log_error("method len too large\n");
        r = EINVAL;
        goto fail;
    }

    if (path_len >= sizeof(request->path)) {
        log_error("path len too large\n");
        r = EINVAL;
        goto fail;
    }

    memcpy(request->path, path, path_len);
    memcpy(request->method, method, method_len);

    request->path[path_len] = '\0';
    request->path_len = path_len;
    request->method[method_len] = '\0';
    request->method_len = method_len;

    for (i = 0; i < num_headers; i++) {
        struct phr_header *header = &headers[i];

        if (!header->name)
            continue;

        r = http_get_header_value(header, "User-Agent", request->agent, sizeof(request->agent));
        if (r == 0)
            continue;
        if (r != EAGAIN)
            goto fail;

        r = http_get_header_value(header, "Host", request->host, sizeof(request->host));
        if (r == 0)
            continue;
        if (r != EAGAIN)
            goto fail;

        r = http_get_header_value(header, "Connection", request->connection, sizeof(request->connection));
        if (r == 0)
            continue;
        if (r != EAGAIN)
            goto fail;

        r = http_get_header_value(header, "Accept", request->accept, sizeof(request->accept));
        if (r == 0)
            continue;
        if (r != EAGAIN)
            goto fail;

        r = http_get_header_value(header, "Content-Length", request->content_length, sizeof(request->content_length));
        if (r == 0)
            continue;
        if (r != EAGAIN)
            goto fail;
    }

    if (request->content_length[0] != '\0') {
        request->body_size = strtoul(request->content_length, NULL, 10);

        log_debug("request body size %lu\n", request->body_size);

        if (request->body_size == 0) {
            if (strlen(request->content_length) != 1 || (request->content_length[0] != '0')) {
                log_error("request body size %lu %s\n", request->body_size, request->content_length);
                r = EINVAL;
                goto fail;
            }
        }

        if ((request->header_size + request->body_size) > request->read)
            return 0;
    }

    if (request->method_len == 3) {
        if (0 == strncmp(request->method, "GET", request->method_len)) {
            request->method_code = HTTP_METHOD_GET;
        }
    } else if (request->method_len == 4) {
        if (0 == strncmp(request->method, "POST", request->method_len)) {
            request->method_code = HTTP_METHOD_POST;
        }
    }

    log_debug("path %s method %s %d headers %d agent %s host %s connection %s accept %s content-length %s\n",
        request->path, request->method, request->method_code, num_headers, request->agent, request->host, request->connection,
        request->accept, request->content_length);

    request->state = HTTP_STATE_READ_COMPLETE;
    return 0;

fail:
    log_error("request parse failed %d\n", r);

    *close = 1;
    return r;
}

int http_request_read(struct http_request *request, int fd, int *close)
{
    int r;
    ssize_t n;

    time_point_capture(&request->read_start);

    bug_on(request->state != HTTP_STATE_READING);

    log_debug("read\n");

    if (request->read >= sizeof(request->buf)) {
        request->state = HTTP_STATE_ERROR;
        return EIO;
    }

    n = read(fd, (char *)request->buf + request->read,
        sizeof(request->buf) - request->read);

    log_debug("read %d\n", n);

    if (n < 0) {
        r = errno;
        return r;
    }

    if (n == 0) {
        *close = 1;
        r = errno;
        return r;
    }

    request->read += n;
    r = http_request_parse(request, close);

    return r;
}

int http_response_write(struct http_response *response, int fd, int *close)
{
    int r;
    ssize_t n;
    struct iovec iov[2];

    log_debug("write\n");

    bug_on(response->state != HTTP_STATE_WRITING);

    time_point_capture(&response->write_start);

    if (response->sent < response->header_size) {
        iov[0].iov_base = (char *)&response->header + response->sent;
        iov[0].iov_len = response->header_size - response->sent;
        iov[1].iov_base = response->body;
        iov[1].iov_len = response->body_size;

        n = writev(fd, iov, (response->body_size) ? 2 : 1);

        log_debug("write header %d\n", n);

    } else {
        size_t off;

        if (response->body_size == 0)
            goto update_state;

        off = response->sent - response->header_size;
        bug_on(!response->body);
        n = write(fd, response->body + off,
            response->body_size - off);

        log_debug("write body %d\n", n);
    }

    if (n < 0) {
        r = errno;
        return r;
    }

    if (n == 0) {
        r = errno;
        return r;
    }

    response->sent += n;

update_state:
    if (response->sent == (response->header_size + response->body_size)) {

        log_debug("write complete\n", n);

        time_point_capture(&response->write_finish);

        response->state = HTTP_STATE_WRITE_COMPLETE;
        /*
        {
            int val = 0;
            if (setsockopt(fd, SOL_TCP, TCP_CORK, &val, sizeof(val))) {
                log_error("cant set tcp no delay\n");
            }

            val = 1;
            if (setsockopt(fd, SOL_TCP, TCP_CORK, &val, sizeof(val))) {
                log_error("cant set tcp no delay\n");
            }
        }
        */
        if (response->close)
            *close = 1;

        return 0;
    }

    return 0;
}

static const char *http_status_message(int status_code)
{
    switch (status_code) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 500:
        return "Internal Server Error";
    case 409:
        return "Conflict";
    default:
        bug_on(1);
        return NULL;
    }
}

#define USERS_PATH_LEN 7 //strlen("/users/")
#define LOCATIONS_PATH_LEN 11 //strlen("/locations/")
#define VISITS_PATH_LEN 8 //strlen("/visits/")
#define NEW_PATH_LEN 3 //strlen("new")
#define VISITS_LEN 7 //strlen("/visits")
#define AVG_LEN 4 //strlen("/avg")

int http_handler(struct http_request *request, struct http_response *response, int *close)
{
    int r, n;
/*
    time_t timestamp;
    struct tm date;
    char date_s[64];
*/
    time_point_capture(&request->handler_start);

    bug_on(request->state != HTTP_STATE_READ_COMPLETE);
    bug_on(response->state != HTTP_STATE_INITED);

    response->status_code = 404;

    if (0 == strncmp(request->path, "/users/", USERS_PATH_LEN)) {
        char *rest_path;
        size_t rest_path_len;

        if (request->path_len <= USERS_PATH_LEN)
            goto reply;
        
        rest_path = request->path + USERS_PATH_LEN;
        rest_path_len = request->path_len - USERS_PATH_LEN;

        if (rest_path_len >= NEW_PATH_LEN && 0 == strncmp(rest_path, "new", NEW_PATH_LEN)) {
            if (request->method_code != HTTP_METHOD_POST)
                goto reply;

            rest_path += NEW_PATH_LEN;
            rest_path_len -= NEW_PATH_LEN;

            request->index = REQ_INDEX_NEW_USER;
            new_user(rest_path, rest_path_len, request, response);

        } else {
            char *visits_pos = strstr(rest_path, "/visits");

            if (visits_pos) {
                uint32_t user_id;
 
                if (visits_pos == rest_path)
                    goto reply;

                if (request->method_code != HTTP_METHOD_GET)
                    goto reply;

                r = string_to_uint32(rest_path, visits_pos - rest_path, &user_id);
                if (r)
                    goto reply;

                rest_path_len = rest_path_len - (visits_pos + VISITS_LEN - rest_path);
                rest_path = visits_pos + VISITS_LEN;

                request->index = REQ_INDEX_GET_USER_VISITS;
                get_user_visits(rest_path, rest_path_len, user_id, request, response);

            } else {

                if (request->method_code != HTTP_METHOD_GET && request->method_code != HTTP_METHOD_POST)
                    goto reply;

                switch (request->method_code)
                {
                case HTTP_METHOD_GET:
                    request->index = REQ_INDEX_GET_USER;
                    get_user(rest_path, rest_path_len, request, response);
                    break;
                case HTTP_METHOD_POST:
                    request->index = REQ_INDEX_UPDATE_USER;
                    update_user(rest_path, rest_path_len, request, response);
                    break;
                default:
                    break;
                }
            }
        }
    } else if (0 == strncmp(request->path, "/locations/", LOCATIONS_PATH_LEN)) {
        char *rest_path;
        size_t rest_path_len;
    
        if (request->path_len <= LOCATIONS_PATH_LEN)
            goto reply;
        
        rest_path = request->path + LOCATIONS_PATH_LEN;
        rest_path_len = request->path_len - LOCATIONS_PATH_LEN;

        if (rest_path_len >= NEW_PATH_LEN && 0 == strncmp(rest_path, "new", NEW_PATH_LEN)) {

            if (request->method_code != HTTP_METHOD_POST)
                goto reply;

            rest_path += NEW_PATH_LEN;
            rest_path_len -= NEW_PATH_LEN;

            request->index = REQ_INDEX_NEW_LOCATION;
            new_location(rest_path, rest_path_len, request, response);

        } else {
            char *avg_pos = strstr(rest_path, "/avg");
            if (avg_pos) {
                uint32_t location_id;

                if (avg_pos == rest_path)
                    goto reply;

                if (request->method_code != HTTP_METHOD_GET)
                    goto reply;

                r = string_to_uint32(rest_path, avg_pos - rest_path, &location_id);
                if (r)
                    goto reply;

                rest_path_len = rest_path_len - (avg_pos + AVG_LEN - rest_path);
                rest_path = avg_pos + AVG_LEN;

                request->index = REQ_INDEX_GET_LOCATION_AVG;
                get_location_average(rest_path, rest_path_len, location_id, request, response);

            } else {

                if (request->method_code != HTTP_METHOD_GET && request->method_code != HTTP_METHOD_POST)
                    goto reply;

                switch (request->method_code)
                {
                case HTTP_METHOD_GET:
                    request->index = REQ_INDEX_GET_LOCATION;
                    get_location(rest_path, rest_path_len, request, response);
                    break;
                case HTTP_METHOD_POST:
                    request->index = REQ_INDEX_UPDATE_LOCATION;
                    update_location(rest_path, rest_path_len, request, response);
                    break;
                default:
                    goto reply;
                }
            }
        }

    } else if (0 == strncmp(request->path, "/visits/", VISITS_PATH_LEN)) {
        char *rest_path;
        size_t rest_path_len;

        if (request->path_len <= VISITS_PATH_LEN)
            goto reply;
        
        rest_path = request->path + VISITS_PATH_LEN;
        rest_path_len = request->path_len - VISITS_PATH_LEN;

        if (rest_path_len >= NEW_PATH_LEN && 0 == strncmp(rest_path, "new", NEW_PATH_LEN)) {

            if (request->method_code != HTTP_METHOD_POST)
                goto reply;

            rest_path += NEW_PATH_LEN;
            rest_path_len -= NEW_PATH_LEN;

            request->index = REQ_INDEX_NEW_VISIT;
            new_visit(rest_path, rest_path_len, request, response);

        } else {

            if (request->method_code != HTTP_METHOD_GET && request->method_code != HTTP_METHOD_POST)
                goto reply;

            switch (request->method_code)
            {
            case HTTP_METHOD_GET:
                request->index = REQ_INDEX_GET_VISIT;
                get_visit(rest_path, rest_path_len, request, response);
                break;
            case HTTP_METHOD_POST:
                request->index = REQ_INDEX_UPDATE_VISIT;
                update_visit(rest_path, rest_path_len, request, response);
            default:
                goto reply;
            }
        }
    }

    if (request->method_code == HTTP_METHOD_POST ||
        strncmp(request->connection, "close", sizeof("close")) == 0) {
        response->close = 1;
    }

    if (response->close) {
        strncpy(response->connection, "close", sizeof("close"));
    }

reply:
/*
    timestamp = time(NULL);
    if (!gmtime_r(&timestamp, &date)) {
        *close = 1;
        return EINVAL;
    }

    if (strftime(date_s, sizeof(date_s), "%a, %d %b %Y %H:%M:%S GMT", &date) == 0) {
        *close = 1;
        return EINVAL;
    }
*/
    n = snprintf(response->header, sizeof(response->header),
        "HTTP/1.1 %d %s\r\n"\
        "Content-Type: %s\r\n"\
        "Content-Length: %lu\r\n"\
        "Connection: %s\r\n"\
        "\r\n", response->status_code, http_status_message(response->status_code),
        response->content_type, response->body_size, response->connection);
    if (n < 0 && n >= sizeof(response->header)) {
        *close = 1;
        return EINVAL;
    }

    response->header_size = n;

    r = 0;
    time_point_capture(&request->handler_finish);
    response->state = HTTP_STATE_WRITING;
    return r;
}

#define INIT_COUNTER(dst, name)   \
    dst->name##_min =  ~(uint64_t)0;    \
    dst->name##_max = 0;    \
    dst->name##_sum = 0;    \
    dst->name##_avg = 0.0;  \

static void http_req_stat_init(struct http_req_stat *req_stat)
{
    INIT_COUNTER(req_stat, read_time)
    INIT_COUNTER(req_stat, handler_time)
    INIT_COUNTER(req_stat, write_time)
    INIT_COUNTER(req_stat, total_time)
    INIT_COUNTER(req_stat, body_size)

    req_stat->count = 0;
    req_stat->handler_path[0] = '\0';
    req_stat->handler_path_len = 0;
    req_stat->total_path[0] = '\0';
    req_stat->total_path_len = 0;
    rwlock_init(&req_stat->lock);
}

void http_stat_init(struct http_stat *stats)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(stats->req_stat); i++)
        http_req_stat_init(&stats->req_stat[i]);
}

#define MERGE_COUNTER(dst, src, name)   \
    if (src->name##_min < dst->name##_min) {  \
        dst->name##_min = src->name##_min;  \
    }                                           \
    if (src->name##_max > dst->name##_max) {    \
        dst->name##_max = src->name##_max;    \
    }                                           \
    dst->name##_sum += src->name##_sum; \
    if (dst->count) {                          \
        dst->name##_avg = (float)dst->name##_sum / dst->count; \
    }

void http_stat_merge(struct http_stat *dst_stats, struct http_stat *src_stats)
{
    int i;
    struct http_req_stat *dst, *src;

    for (i = 0; i < ARRAY_SIZE(dst_stats->req_stat); i++) {
        dst = &dst_stats->req_stat[i];
        src = &src_stats->req_stat[i];

        rwlock_lock(&dst->lock);
        rwlock_read_lock(&src->lock);

        dst->count += src->count;

        MERGE_COUNTER(dst, src, read_time)

        if (src->handler_time_max > dst->handler_time_max) {
            strncpy(dst->handler_path, src->handler_path, src->handler_path_len + 1);
            dst->handler_path_len = src->handler_path_len;
        }

        MERGE_COUNTER(dst, src, handler_time)
        MERGE_COUNTER(dst, src, write_time)

        if (src->total_time_max > dst->total_time_max) {
            strncpy(dst->total_path, src->total_path, src->total_path_len + 1);
            dst->total_path_len = src->total_path_len;
        }

        MERGE_COUNTER(dst, src, total_time)
        MERGE_COUNTER(dst, src, body_size)

        rwlock_read_unlock(&src->lock);
        rwlock_unlock(&dst->lock);
    }
}

#define UPDATE_COUNTER(dst, name, value)   \
    if (value < dst->name##_min) {  \
        dst->name##_min = value;    \
    }                                   \
    if (value > dst->name##_max) {  \
        dst->name##_max = value;    \
    }                               \
    dst->name##_sum += value;       \
    dst->name##_avg = (float)dst->name##_sum / dst->count;

void http_stat_request(struct http_stat *stats, struct http_request *request, struct http_response *response)
{
    struct http_req_stat *req_stat;
    uint64_t read_time, write_time, handler_time, total_time, body_size;

    if (request->index < 0 || request->index >= ARRAY_SIZE(stats->req_stat))
        return;

    read_time = time_point_sub(&request->read_finish, &request->read_start);
    handler_time = time_point_sub(&request->handler_finish, &request->handler_start);
    write_time = time_point_sub(&response->write_finish, &response->write_start);
    total_time = time_point_sub(&response->write_finish, &request->read_start);
    body_size = response->body_size;

    req_stat = &stats->req_stat[request->index];
    rwlock_lock(&req_stat->lock);

    req_stat->count++;

    UPDATE_COUNTER(req_stat, read_time, read_time);

    if (handler_time > req_stat->handler_time_max) {
        strncpy(req_stat->handler_path, request->path, request->path_len + 1);
        req_stat->handler_path_len = request->path_len;
    }

    UPDATE_COUNTER(req_stat, handler_time, handler_time);
    UPDATE_COUNTER(req_stat, write_time, write_time);

    if (total_time > req_stat->total_time_max) {
        strncpy(req_stat->total_path, request->path, request->path_len + 1);
        req_stat->total_path_len = request->path_len;
    }

    UPDATE_COUNTER(req_stat, total_time, total_time);
    UPDATE_COUNTER(req_stat, body_size, body_size);

    rwlock_unlock(&req_stat->lock);
}

static void http_req_stat_dump(const char *name, struct http_req_stat *req_stat)
{
    rwlock_read_lock(&req_stat->lock);

    log_info("%s R[%llu %f %llu] H[%llu %f %llu] W[%llu %f %llu] T[%llu %f %llu] S[%llu %f %llu] %llu\n",
        name, req_stat->read_time_min, req_stat->read_time_avg, req_stat->read_time_max,
        req_stat->handler_time_min, req_stat->handler_time_avg, req_stat->handler_time_max,
        req_stat->write_time_min, req_stat->write_time_avg, req_stat->write_time_max,
        req_stat->total_time_min, req_stat->total_time_avg, req_stat->total_time_max,
        req_stat->body_size_min, req_stat->body_size_avg, req_stat->body_size_max,
        req_stat->count);

    log_info("%s paths %s %s\n", name, req_stat->handler_path, req_stat->total_path);

    rwlock_read_unlock(&req_stat->lock);
}

void http_stat_dump(struct http_stat *stats)
{
    const char *names[ARRAY_SIZE(stats->req_stat)] = 
        {"get_user", "get_location", "get_visit",
        "update_user", "update_location", "update_visit",
        "new_user", "new_location", "new_visit",
        "get_user_visits", "get_location_avg"};
    int i;

    bug_on(ARRAY_SIZE(stats->req_stat) != ARRAY_SIZE(names));

    for (i = 0; i < ARRAY_SIZE(stats->req_stat); i++) {
        http_req_stat_dump(names[i], &stats->req_stat[i]);
    }
}