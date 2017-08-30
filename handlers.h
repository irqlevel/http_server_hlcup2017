#pragma once

#include "base.h"
#include "misc.h"
#include "http.h"

void get_user(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void get_visit(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void get_location(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void new_user(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void new_location(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void new_visit(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void update_user(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void update_location(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void update_visit(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp);

void get_user_visits(const char *rest_path, size_t rest_path_len,
    uint32_t user_id, struct http_request *req, struct http_response *resp);

void get_location_average(const char *rest_path, size_t rest_path_len,
    uint32_t location_id, struct http_request *req, struct http_response *resp);