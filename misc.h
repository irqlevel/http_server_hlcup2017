#pragma once

#include "base.h"
#include "jsmn.h"

#define MAX_UNICODE_CHARS 50
#define MAX_STRING_LEN (4 * MAX_UNICODE_CHARS)
#define MAX_STRING_SIZE (MAX_STRING_LEN + 1)

struct json_string {
    char value[MAX_STRING_SIZE];
    int exists;
    int is_null;
};

struct json_int64 {
    int64_t value;
    int exists;
    int is_null;
};

struct json_uint32 {
    uint32_t value;
    int exists;
    int is_null;
};

static inline void json_string_clear(struct json_string *s)
{
    s->exists = 0;
    s->is_null = 0;
    s->value[0] = '\0';
    s->value[MAX_STRING_LEN] = '\0';
}

static inline void json_int64_clear(struct json_int64 *s)
{
    s->exists = 0;
    s->is_null = 0;
    s->value = 0;
}

static inline void json_uint32_clear(struct json_uint32 *s)
{
    s->exists = 0;
    s->is_null = 0;
    s->value = 0;
}

static inline int json_string_is_valid(struct json_string *s)
{
    if (s->exists && !s->is_null &&
        s->value[MAX_STRING_LEN] == '\0' && strlen(s->value) != 0)
        return 1;
    return 0;
}

static inline int json_int64_is_valid(struct json_int64 *s)
{
    if (s->exists && !s->is_null)
        return 1;
    return 0;
}

static inline int json_uint32_is_valid(struct json_uint32 *s)
{
    if (s->exists && !s->is_null)
        return 1;
    return 0;
}

struct user_data {
    struct json_uint32 id;
    struct json_string email;
    struct json_string first_name;
    struct json_string last_name;
    struct json_string gender;
    struct json_int64 birth_date;
};

struct visit_data {
    struct json_uint32 id;
    struct json_uint32 location;
    struct json_uint32 user;
    struct json_int64 visited_at;
    struct json_uint32 mark;
};

struct location_data {
    struct json_uint32 id;
    struct json_string place;
    struct json_string country;
    struct json_string city;
    struct json_uint32 distance;
};

int hex_string_to_uint32(const char *s, size_t len, uint32_t *presult);

int string_to_uint32(const char *s, size_t len, uint32_t *presult);

int string_to_int64(const char *s, size_t len, int64_t *presult);

int string_copy_len(char *dst, size_t dst_size, const char *src, size_t src_len);

int string_copy(char *dst, size_t dst_size, const char *src);

int json_string_set(struct json_string *s, const char *src, size_t src_len);

int json_int64_set(struct json_int64 *s, const char *src, size_t src_len);

int json_uint32_set(struct json_uint32 *s, const char *src, size_t src_len);

int parse_json_user_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct user_data *user, size_t *used_tokens);

int parse_json_location_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct location_data *location, size_t *used_tokens);

int parse_json_visit_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct visit_data *visit, size_t *used_tokens);

struct buf {
    char *ptr;
    size_t pos;
    size_t size;
};

int buf_init(struct buf *buf, size_t size);
int buf_append(struct buf *buf, const char *src, size_t src_len);
int buf_printf(struct buf *buf, const char *fmt, ...);
char *buf_reset(struct buf *buf);
void buf_free(struct buf *buf);

struct sbuf {
    char *ptr;
    size_t pos;
    size_t size;
};

void sbuf_init(struct sbuf *buf, void *ptr, size_t size);
int sbuf_append(struct sbuf *buf, const char *src, size_t src_len);
int sbuf_printf(struct sbuf *buf, const char *fmt, ...);

struct query_key {
    const char *key;
    size_t key_len;
    const char *value;
    size_t value_len;
};

const char *string_chr(const char *s, size_t len, char c);

int parse_query(const char *path, size_t path_len, struct query_key *keys, size_t max_keys);

int has_query(const char *path, size_t path_len);

int url_decode(const char *src, size_t src_len, char *dst, size_t dst_len);