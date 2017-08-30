#include "handlers.h"
#include "logger.h"
#include "db.h"
#include "server.h"

static int error_to_http_status_code(int r)
{
    log_debug("error %d\n", r);

    switch (r) {
    case 0:
        return 200;
    case ENOENT:
        return 404;
    case EINVAL:
        return 400;
    case EEXIST:
        return 409;
    case ENOMEM:
        log_error("no memory error\n");
        return 500;
    default:
        log_error("unknown error %d\n", r);
        return 500;
    }
}

void prepare_response(struct http_response *resp, int r, char *body, size_t body_size)
{
    resp->status_code = error_to_http_status_code(r);

    if (body == NULL) {
        body_size = 3;
        body = malloc(body_size);
        if (body) {
            strncpy(body, "{}\n", body_size);
        }
    }

    resp->body = body;
    resp->body_size = body_size;

    log_debug("response status %d body_size %lu\n", resp->status_code, resp->body_size);
}

void get_user(const char *rest_path, size_t rest_path_len,
                    struct http_request *req, struct http_response *resp)
{
    uint32_t user_id;
    int r;
    void *data = NULL;
    size_t data_size = 0;
    struct sbuf buf;

    log_debug("get_user: rest_path %.*s\n", rest_path_len, rest_path);

    r = string_to_uint32(rest_path, rest_path_len, &user_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    sbuf_init(&buf, resp->body_buf, sizeof(resp->body_buf));
    r = db_get_user(&get_server()->db, user_id, &buf);
    if (r)
        goto out;

    data = buf.ptr;
    data_size = buf.pos;

out:
    prepare_response(resp, r, data, data_size);
}

void get_location(const char *rest_path, size_t rest_path_len,
                    struct http_request *req, struct http_response *resp)
{
    uint32_t location_id;
    int r;
    void *data = NULL;
    size_t data_size = 0;
    struct sbuf buf;

    log_debug("get_location: rest_path %.*s\n", rest_path_len, rest_path);

    r = string_to_uint32(rest_path, rest_path_len, &location_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    sbuf_init(&buf, resp->body_buf, sizeof(resp->body_buf));
    r = db_get_location(&get_server()->db, location_id, &buf);
    if (r)
        goto out;

    data = buf.ptr;
    data_size = buf.pos;

out:
    prepare_response(resp, r, data, data_size);
}

void get_visit(const char *rest_path, size_t rest_path_len,
                    struct http_request *req, struct http_response *resp)
{
    uint32_t visit_id;
    int r;
    struct sbuf buf;
    size_t data_size = 0;
    void *data = NULL;

    log_debug("get_visit: rest_path %.*s\n", rest_path_len, rest_path);

    r = string_to_uint32(rest_path, rest_path_len, &visit_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    sbuf_init(&buf, resp->body_buf, sizeof(resp->body_buf));

    r = db_get_visit(&get_server()->db, visit_id, &buf);
    if (r)
        goto out;

    data = buf.ptr;
    data_size = buf.pos;

out:
    prepare_response(resp, r, data, data_size);
}

void new_user(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct user_data user;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    int r;

    log_debug("new_user: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len) {
        r = has_query(rest_path, rest_path_len);
        if (r)
            goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_user_data(tokens, nr_tokens, body, body_size, &user, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_new_user(&get_server()->db, &user);

out:
    prepare_response(resp, r, NULL, 0);
}

void new_location(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct location_data location;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    int r;

    log_debug("new_location: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len) {
        r = has_query(rest_path, rest_path_len);
        if (r)
            goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_location_data(tokens, nr_tokens, body, body_size, &location, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_new_location(&get_server()->db, &location);

out:
    prepare_response(resp, r, NULL, 0);
}

void new_visit(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct visit_data visit;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    int r;

    log_debug("new_visit: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len) {
        r = has_query(rest_path, rest_path_len);
        if (r)
            goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_visit_data(tokens, nr_tokens, body, body_size, &visit, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_new_visit(&get_server()->db, &visit);

out:
    prepare_response(resp, r, NULL, 0);
}

void update_user(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct user_data user;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    uint32_t user_id;
    int r;
    const char *query_pos;

    log_debug("update_user: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len == 0) {
        r = EINVAL;
        goto out;
    }

    query_pos = string_chr(rest_path, rest_path_len, '?');
    if (query_pos) {
        rest_path_len = query_pos - rest_path;
    }

    r = string_to_uint32(rest_path, rest_path_len, &user_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_user_data(tokens, nr_tokens, body, body_size, &user, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_update_user(&get_server()->db, user_id, &user);

out:
    prepare_response(resp, r, NULL, 0);
}

void update_location(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct location_data location;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    uint32_t location_id;
    const char *query_pos;
    int r;

    log_debug("update_location: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len == 0) {
        r = EINVAL;
        goto out;
    }

    query_pos = string_chr(rest_path, rest_path_len, '?');
    if (query_pos) {
        rest_path_len = query_pos - rest_path;
    }

    r = string_to_uint32(rest_path, rest_path_len, &location_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_location_data(tokens, nr_tokens, body, body_size, &location, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_update_location(&get_server()->db, location_id, &location);

out:
    prepare_response(resp, r, NULL, 0);
}

void update_visit(const char *rest_path, size_t rest_path_len,
    struct http_request *req, struct http_response *resp)
{
	jsmn_parser p;
	jsmntok_t tokens[100];
    struct visit_data visit;
    size_t used_tokens, nr_tokens;
    char *body;
    size_t body_size;
    uint32_t visit_id;
    const char *query_pos;
    int r;

    log_debug("update_visit: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len == 0) {
        r = EINVAL;
        goto out;
    }

    query_pos = string_chr(rest_path, rest_path_len, '?');
    if (query_pos) {
        rest_path_len = query_pos - rest_path;
    }

    r = string_to_uint32(rest_path, rest_path_len, &visit_id);
    if (r) {
        r = ENOENT;
        goto out;
    }

    body_size = http_request_body_size(req);
    if (!body_size) {
        r = EINVAL;
        goto out;
    }
    body = http_request_body(req);

    jsmn_init(&p);
    r = jsmn_parse(&p, body, body_size, tokens, 100);
    if (r < 0) {
        r = EINVAL;
        goto out;
    }

    nr_tokens = r;
    r = parse_json_visit_data(tokens, nr_tokens, body, body_size, &visit, &used_tokens);
    if (r)
        goto out;

    if (used_tokens != nr_tokens) {
        r = EINVAL;
        goto out;
    }

    r = db_update_visit(&get_server()->db, visit_id, &visit);

out:
    prepare_response(resp, r, NULL, 0);
}

void get_user_visits(const char *rest_path, size_t rest_path_len, uint32_t user_id,
    struct http_request *req, struct http_response *resp)
{
    int64_t *from_date = NULL, *to_date = NULL;
    const char *country = NULL;
    uint32_t *to_distance = NULL;
    int64_t from_date_s, to_date_s;
    char country_s[MAX_STRING_SIZE];
    uint32_t to_distance_s;
    struct sbuf buf;
    void *data = NULL;
    size_t data_size = 0;
    int r, n, i;
    struct query_key keys[4];
    struct query_key *key;

    log_debug("get_user_visits: rest_path %.*s\n", rest_path_len, rest_path);

    if (rest_path_len) {
        n = parse_query(rest_path, rest_path_len, keys, ARRAY_SIZE(keys));
        if (n < 0) {
            r = EINVAL;
            goto out;
        }
        for (i = 0; i < n; i++) {
            key = &keys[i];
            if (strncmp(key->key, "fromDate", key->key_len) == 0) {
                r = string_to_int64(key->value, key->value_len, &from_date_s);
                if (r)
                    goto out;
                from_date = &from_date_s;
            } else if (strncmp(key->key, "toDate", key->key_len) == 0) {
                r = string_to_int64(key->value, key->value_len, &to_date_s);
                if (r)
                    goto out;
                to_date = &to_date_s;
            } else if (strncmp(key->key, "toDistance", key->key_len) == 0) {
                r = string_to_uint32(key->value, key->value_len, &to_distance_s);
                if (r)
                    goto out;
                to_distance = &to_distance_s;
            } else if (strncmp(key->key, "country", key->key_len) == 0) {
                if (key->value_len >= ARRAY_SIZE(country_s)) {
                    r = EINVAL;
                    goto out;
                }

                r = url_decode(key->value, key->value_len, country_s, ARRAY_SIZE(country_s) - 1);
                if (r < 0) {
                    r = EINVAL;
                    goto out;
                }

                country_s[r] = '\0';
                country = country_s;
            } else {
                r = EINVAL;
                goto out;
            }
        }
    }

    sbuf_init(&buf, resp->body_buf, sizeof(resp->body_buf));

    r = db_get_user_visits(&get_server()->db, user_id, from_date, to_date, country, to_distance, &buf);
    if (r)
        goto out;

    data_size = buf.pos;
    data = buf.ptr;

out:
    prepare_response(resp, r, data, data_size);
}

void get_location_average(const char *rest_path, size_t rest_path_len, uint32_t location_id,
    struct http_request *req, struct http_response *resp)
{
    int r, n, i;
    char *data = NULL;
    size_t data_size = 0;
    int64_t *from_date = NULL, *to_date = NULL;
    uint32_t *from_age = NULL, *to_age = NULL;
    const char *gender = NULL;
    int64_t from_date_s, to_date_s;
    uint32_t from_age_s, to_age_s;
    char gender_s[2];
    struct query_key keys[5];
    struct query_key *key;
    struct sbuf buf;

    log_debug("get_location_average: location_id %u rest_path %lu %.*s\n",
        location_id, rest_path_len, rest_path_len, rest_path);

    if (rest_path_len) {
        n = parse_query(rest_path, rest_path_len, keys, ARRAY_SIZE(keys));
        if (n < 0) {
            log_error("can't parse query\n");
            r = EINVAL;
            goto out;
        }
        for (i = 0; i < n; i++) {
            key = &keys[i];
            if (strncmp(key->key, "fromDate", key->key_len) == 0) {
                r = string_to_int64(key->value, key->value_len, &from_date_s);
                if (r)
                    goto out;
                from_date = &from_date_s;
            } else if (strncmp(key->key, "toDate", key->key_len) == 0) {
                r = string_to_int64(key->value, key->value_len, &to_date_s);
                if (r)
                    goto out;
                to_date = &to_date_s;
            } else if (strncmp(key->key, "fromAge", key->key_len) == 0) {
                r = string_to_uint32(key->value, key->value_len, &from_age_s);
                if (r)
                    goto out;
                from_age = &from_age_s;
            } else if (strncmp(key->key, "toAge", key->key_len) == 0) {
                r = string_to_uint32(key->value, key->value_len, &to_age_s);
                if (r)
                    goto out;
                to_age = &to_age_s;
            } else if (strncmp(key->key, "gender", key->key_len) == 0) {
                if (key->value_len != 1 || (key->value[0] != 'm' && key->value[0] != 'f')) {
                    r = EINVAL;
                    goto out;
                }
                gender_s[0] = key->value[0];
                gender_s[1] = '\0';
                gender = gender_s;
            } else {
                log_debug("unknown query key %.*s\n", key->key_len, key->key);
                r = EINVAL;
                goto out;
            }
        }
    }

    sbuf_init(&buf, resp->body_buf, sizeof(resp->body_buf));
    r = db_get_location_average(&get_server()->db, location_id, from_date, to_date,
            from_age, to_age, gender, &buf);
    if (r) {
        log_debug("db_get_location_average %d\n", r);
        goto out;
    }

    data_size = buf.pos;
    data = buf.ptr;

out:
    prepare_response(resp, r, data, data_size);
}