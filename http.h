#pragma once

#include "base.h"
#include "rwlock.h"
#include "picohttpparser.h"

enum {
    HTTP_STATE_INITED,
    HTTP_STATE_READING,
    HTTP_STATE_READ_COMPLETE,
    HTTP_STATE_WRITING,
    HTTP_STATE_WRITE_COMPLETE,
    HTTP_STATE_ERROR,
};

enum {
    HTTP_METHOD_UNK,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
};

struct time_point {
    struct timeval value;
    int valid;
};

struct http_request
{
    char buf[512];
    size_t read;
    size_t header_size;
    size_t body_size;
    size_t method_len;
    size_t path_len;
    int method_code;
    int state;
    char method[32];
    char path[256];
    char agent[64];
    char host[32];
    char accept[32];
    char connection[32];
    char content_length[32];
    struct time_point read_start;
    struct time_point read_finish;
    struct time_point handler_start;
    struct time_point handler_finish;
    int index;
};

struct http_response
{
    char header[512];
    char body_buf[8192];
    size_t header_size;
    size_t body_size;
    size_t sent;
    char *body;
    int state;
    int status_code;
    int close;
    char content_type[32];
    char connection[32];
    struct time_point write_start;
    struct time_point write_finish;
};

enum {
    REQ_INDEX_INVALID = -1,
    REQ_INDEX_GET_USER = 0,
    REQ_INDEX_GET_LOCATION,
    REQ_INDEX_GET_VISIT,
    REQ_INDEX_UPDATE_USER,
    REQ_INDEX_UPDATE_LOCATION,
    REQ_INDEX_UPDATE_VISIT,
    REQ_INDEX_NEW_USER,
    REQ_INDEX_NEW_LOCATION,
    REQ_INDEX_NEW_VISIT,
    REQ_INDEX_GET_USER_VISITS,
    REQ_INDEX_GET_LOCATION_AVG,
    REQ_INDEX_MAX
};

struct http_req_stat {
    uint64_t read_time_min;
    uint64_t read_time_sum;
    uint64_t read_time_max;
    float read_time_avg;

    uint64_t handler_time_min;
    uint64_t handler_time_max;
    uint64_t handler_time_sum;
    float handler_time_avg;
   
    uint64_t write_time_min;
    uint64_t write_time_max;
    uint64_t write_time_sum;
    float write_time_avg;

    uint64_t total_time_min;
    uint64_t total_time_max;
    uint64_t total_time_sum;
    float total_time_avg;

    uint64_t count;

    uint64_t body_size_min;
    uint64_t body_size_max;
    uint64_t body_size_sum;
    float body_size_avg;

    char handler_path[256];
    size_t handler_path_len;

    char total_path[256];
    size_t total_path_len;

    struct rwlock lock;
};

struct http_stat {
    struct http_req_stat req_stat[REQ_INDEX_MAX]; 
};

static inline char *http_request_body(struct http_request *request)
{
    return request->buf + request->header_size;
}

static inline size_t http_request_body_size(struct http_request *request)
{
    return request->body_size;
}

void http_request_init(struct http_request *request);
void http_response_init(struct http_response *response);

void http_request_reset(struct http_request *request);
void http_response_reset(struct http_response *response);

int http_request_read(struct http_request *request, int fd, int *close);

int http_response_write(struct http_response *response, int fd, int *close);

int http_handler(struct http_request *request, struct http_response *response, int *close);

void http_stat_init(struct http_stat *stats);

void http_stat_request(struct http_stat *stats, struct http_request *request, struct http_response *response);

void http_stat_merge(struct http_stat *dst_stats, struct http_stat *src_stats);

void http_stat_dump(struct http_stat *stats);