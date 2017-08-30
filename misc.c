#include "misc.h"
#include "logger.h"
#include "utf.h"

static int hex_to_digit(char c, uint32_t *result)
{
    if (c >= '0' && c <= '9')
    {
        *result = c - '0';
        return 0;
    }

    if (c >= 'a' && c <= 'f')
    {
        *result = c - 'a' + 10;
        return 0;
    }

    if (c >= 'A' && c <= 'F')
    {
        *result = c - 'A' + 10;
        return 0;
    }

    return EINVAL;
}

int hex_string_to_uint32(const char *s, size_t len, uint32_t *presult)
{
    size_t i;
    uint32_t result;
    uint32_t digit;
    int r;

    if (len == 0) {
        log_error("unexpected string %.*s\n", len, s);
        return EINVAL;
    }

    result = 0;
    for (i = 0; i < len; i++) {
        if (s[i] == '\0') {
            if (i == 0) {
                log_error("unexpected string %.*s\n", len, s);
                return EINVAL;
            }
            goto out;
        }

        r = hex_to_digit(s[i], &digit);
        if (r) {
            log_error("unexpected string %.*s\n", len, s);
            return EINVAL;            
        }

        result = result * 16 + digit;
    }

out:
    *presult = result;
    return 0;
}

int string_to_uint32(const char *s, size_t len, uint32_t *presult)
{
    size_t i;
    uint32_t result;

    if (len == 0) {
        log_error("unexpected string %.*s\n", len, s);
        return EINVAL;
    }

    result = 0;
    for (i = 0; i < len; i++) {
        if (s[i] == '\0') {
            if (i == 0) {
                log_error("unexpected string %.*s\n", len, s);
                return EINVAL;
            }
            goto out;
        }

        if (s[i] < '0' || s[i] > '9') {
            log_debug("unexpected string %.*s\n", len, s);
            return EINVAL;
        }

        result = result * 10 + (s[i] - '0');
    }

out:
    *presult = result;
    return 0;
}

int string_to_int64(const char *s, size_t len, int64_t *presult)
{
    int64_t result;
    size_t i;
    int minus = 0;

    if (len == 0) {
        log_error("unexpected string %.*s\n", len, s);
        return EINVAL;
    }

    result = 0;
    for (i = 0; i < len; i++) {
        if (s[i] == '-') {
            if (minus) {
                log_error("unexpected string %.*s\n", len, s);
                return EINVAL;
            } else {
                if (i != 0) {
                    log_error("unexpected string %.*s\n", len, s);
                    return EINVAL;
                }

                minus = 1;
                continue;
            }
        }

        if (s[i] == '\0') {
            if (i == 0) {
                log_error("unexpected string %.*s\n", len, s);
                return EINVAL;
            }
            goto out;
        }

        if (s[i] < '0' || s[i] > '9') {
            log_debug("unexpected string %.*s\n", len, s);
            return EINVAL;
        }
        result = result * 10 + (s[i] - '0');
    }

out:
    *presult = (minus) ? (-result) : (result);
    return 0;
}

int string_copy_len(char *dst, size_t dst_size, const char *src, size_t src_len)
{
    if (src_len >= dst_size)
        return EINVAL;
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return 0;
}

int string_copy(char *dst, size_t dst_size, const char *src)
{
    return string_copy_len(dst, dst_size, src, strlen(src));
}

int json_string_set(struct json_string *s, const char *src, size_t src_len)
{
    s->exists = 0;
    s->is_null = 0;

    if (strncmp(src, "null", src_len) == 0) {
        s->is_null = 1;
    } else {
        int r;

        r = ut8_parse_escaped_string(src, src_len, s->value, sizeof(s->value) - 1);
        if (r < 0)
            return EINVAL;

        s->value[r] = '\0';
        s->exists = 1;
    }

    return 0;
}

int json_int64_set(struct json_int64 *s, const char *src, size_t src_len)
{
    s->exists = 0;
    s->is_null = 0;

    if (strncmp(src, "null", src_len) == 0) {
        s->is_null = 1;
    } else {
        int r;

        r = string_to_int64(src, src_len, &s->value);
        if (r)
            return r;

        s->exists = 1;
    }

    return 0;
}

int json_uint32_set(struct json_uint32 *s, const char *src, size_t src_len)
{
    s->exists = 0;
    s->is_null = 0;

    if (strncmp(src, "null", src_len) == 0) {
        s->is_null = 1;
    } else {
        int r;

        r = string_to_uint32(src, src_len, &s->value);
        if (r)
            return r;

        s->exists = 1;
    }

    return 0;
}


static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}

	return -1;
}

int parse_json_user_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct user_data *user, size_t *used_tokens)
{
    jsmntok_t *token;
    int r, i;

    *used_tokens = 0;
    if (nr_tokens <= 1 || tokens[0].type != JSMN_OBJECT)
        return EINVAL;

    json_uint32_clear(&user->id);
    json_string_clear(&user->email);
    json_string_clear(&user->first_name);
    json_string_clear(&user->last_name);
    json_string_clear(&user->gender);
    json_int64_clear(&user->birth_date);

    for (i = 1; i < nr_tokens; i++) {
        token = &tokens[i];
        switch (token->type)
        {
        case JSMN_OBJECT:
            r = 0;
            goto out;
        case JSMN_STRING: {
            const char *value;
            size_t value_len;

            if (i == (nr_tokens - 1)) {
                log_error("unexpected string token position\n");
                return EINVAL;
            }

            value = data + tokens[i+1].start;
            value_len = tokens[i+1].end - tokens[i+1].start;

            if (jsoneq(data, token, "id") == 0) {
                r = json_uint32_set(&user->id, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "first_name") == 0) {
                r = json_string_set(&user->first_name, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "last_name") == 0) {
                r = json_string_set(&user->last_name, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "email") == 0) {
                r = json_string_set(&user->email, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "birth_date") == 0) {
                r = json_int64_set(&user->birth_date, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "gender") == 0) {
                r = json_string_set(&user->gender, value, value_len);
                if (r)
                    return r;
            } else {
                log_error("unexpected object key %.*s\n",
                    token[i].end-token[i].start, data + token[i].start);
                return EINVAL;
            }
            i++;
            break;
        }
        default:
            log_error("unexpected token type %d\n", token->type);
            return EINVAL;
        }
    }

out:
    *used_tokens = i;

    return r;
}


int parse_json_location_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct location_data *location, size_t *used_tokens)
{
    jsmntok_t *token;
    int r, i;

    *used_tokens = 0;

    if (nr_tokens <= 1 || tokens[0].type != JSMN_OBJECT)
        return EINVAL;

    json_uint32_clear(&location->id);
    json_string_clear(&location->place);
    json_string_clear(&location->country);
    json_string_clear(&location->city);
    json_uint32_clear(&location->distance);

    for (i = 1; i < nr_tokens; i++) {
        token = &tokens[i];
        switch (token->type)
        {
        case JSMN_OBJECT:
            r = 0;
            goto out;
        case JSMN_STRING: {
            const char *value;
            size_t value_len;

            if (i == (nr_tokens - 1)) {
                log_error("unexpected string token position\n");
                return EINVAL;
            }

            value = data + tokens[i+1].start;
            value_len = tokens[i+1].end - tokens[i+1].start;

            if (jsoneq(data, token, "id") == 0) {
                r = json_uint32_set(&location->id, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "place") == 0) {
                r = json_string_set(&location->place, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "city") == 0) {
                r = json_string_set(&location->city, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "country") == 0) {
                r = json_string_set(&location->country, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "distance") == 0) {
                r = json_uint32_set(&location->distance, value, value_len);
                if (r)
                    return r;
            } else {
                log_error("unexpected object key %.*s\n",
                    token[i].end-token[i].start, data + token[i].start);
                return EINVAL;
            }
            i++;
            break;
        }
        default:
            log_error("unexpected token type %d\n", token->type);
            return EINVAL;
        }
    }

out:
    *used_tokens = i;

    return r;
}

int parse_json_visit_data(jsmntok_t *tokens, size_t nr_tokens,
                const char *data, size_t size,
                struct visit_data *visit, size_t *used_tokens)
{
    jsmntok_t *token;
    int r, i;

    *used_tokens = 0;
    if (nr_tokens <= 1 || tokens[0].type != JSMN_OBJECT)
        return EINVAL;

    json_uint32_clear(&visit->id);
    json_uint32_clear(&visit->location);
    json_uint32_clear(&visit->user);
    json_int64_clear(&visit->visited_at);
    json_uint32_clear(&visit->mark);

    for (i = 1; i < nr_tokens; i++) {
        token = &tokens[i];
        switch (token->type)
        {
        case JSMN_OBJECT:
            r = 0;
            goto out;
        case JSMN_STRING: {
            const char *value;
            size_t value_len;

            if (i == (nr_tokens - 1)) {
                log_error("unexpected string token position\n");
                return EINVAL;
            }

            value = data + tokens[i+1].start;
            value_len = tokens[i+1].end - tokens[i+1].start;

            if (jsoneq(data, token, "id") == 0) {
                r = json_uint32_set(&visit->id, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "user") == 0) {
                r = json_uint32_set(&visit->user, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "location") == 0) {
                r = json_uint32_set(&visit->location, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "visited_at") == 0) {
                r = json_int64_set(&visit->visited_at, value, value_len);
                if (r)
                    return r;
            } else if (jsoneq(data, token, "mark") == 0) {
                r = json_uint32_set(&visit->mark, value, value_len);
                if (r)
                    return r;
            } else {
                log_error("unexpected object key %.*s\n",
                    token[i].end-token[i].start, data + token[i].start);
                return EINVAL;
            }
            i++;
            break;
        }
        default:
            log_error("unexpected token type %d\n", token->type);
            return EINVAL;
        }
    }

out:
    *used_tokens = i;

    return r;
}

int buf_init(struct buf *buf, size_t size)
{
    buf->ptr = malloc(size);
    if (!buf->ptr)
        return ENOMEM;

    buf->size = size;
    buf->pos = 0;
    return 0;
}

static int buf_grow(struct buf *buf)
{
    size_t size = 2 * buf->size;
    char *ptr, *old_ptr;

    ptr = malloc(size);
    if (!ptr)
        return ENOMEM;

    memcpy(ptr, buf->ptr, buf->pos);
    old_ptr = buf->ptr;
    buf->ptr = ptr;
    buf->size = size;
    free(old_ptr);

    return 0;
}

int buf_append(struct buf *buf, const char *src, size_t src_len)
{
    int i, r;

    for (i = 0; i < 5; i++) {
        if ((buf->size - buf->pos) >= src_len) {
            memcpy(buf->ptr + buf->pos, src, src_len);
            buf->pos += src_len;
            return 0;
        } else {
            r = buf_grow(buf);
            if (r)
                return r;
        }
    }

    return ENOMEM;
}

int buf_printf(struct buf *buf, const char *fmt, ...)
{
    int n, i, r;
    va_list args;

    bug_on(!buf->ptr);

    for (i = 0; i < 5; i++) {
        va_start(args, fmt);
        n = vsnprintf(buf->ptr + buf->pos, buf->size - buf->pos, fmt, args);
        va_end(args);
        if (n < 0)
            return EINVAL;

        if (n < (buf->size - buf->pos)) {
            buf->pos += n;
            return 0;
        }

        r = buf_grow(buf);
        if (r)
            return r;
    }

    return ENOMEM;
}

char *buf_reset(struct buf *buf)
{
    char *ptr = buf->ptr;

    buf->ptr = NULL;
    return ptr;
}

void buf_free(struct buf *buf)
{
    if (buf->ptr)
        free(buf->ptr);
}

int parse_query(const char *path, size_t path_len, struct query_key *keys, size_t max_keys)
{
    size_t i, pos, key_len = 0;
    const char *curr;
    const char *key;
    const char *value;

    if (path_len <= 1)
        return -1;
    if (path[0] != '?')
        return -1;
    if (max_keys == 0)
        return -1;

    key = value = NULL;
    curr = &path[1];
    pos = 0;
    for (i = 1; i < path_len; i++) {
        switch (*curr) {
        case '?':
            return -1;
        case '/':
            return -1;
        case '=':
            if (!key) {
                return -1;
            }
            keys[pos].key = key;
            keys[pos].key_len = key_len = curr - key;
            break;
        case '&':
            if (!value || !key) {
                return -1;
            }
            keys[pos].value = value;
            keys[pos].value_len = curr - value;
            pos++;
            key = value = NULL;
            key_len = 0;
            if (pos == max_keys) {
                return -1;
            }
            break;
        default:
            if (!key) {
                key = curr;
            } else if (key_len && !value) {
                value = curr;
            }
        }
        curr++;
    }

    if (!value || !key) {
        return -1;
    }

    keys[pos].value = value;
    keys[pos].value_len = curr - value;
    pos++;

    return pos;
}

int has_query(const char *path, size_t path_len)
{
    if (path_len == 0)
        return EINVAL;
    if (path[0] != '?')
        return EINVAL;
    return 0;
}

const char *string_chr(const char *s, size_t len, char c)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (s[i] == c)
            return &s[i];
    }

    return NULL;
}

static inline int ishex(int x)
{
	return	(x >= '0' && x <= '9')	||
		(x >= 'a' && x <= 'f')	||
		(x >= 'A' && x <= 'F');
}

int url_decode(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    char *out; 
    const char *end = src + src_len;
    int c;

    for (out = dst; src < end; out++) {
        c = *src++;
        if (c == '+') {
            c = ' '; 
        } else if (c == '%') {  
            if (!ishex(*src++)  || !ishex(*src++) ||
                !sscanf(src - 2, "%2x", &c))
            return -1;
        }

        if ((out - dst) >= dst_len)
                return -1;

        *out = c;
    }

    return out - dst;
}

void sbuf_init(struct sbuf *buf, void *ptr, size_t size)
{
    buf->ptr = ptr;
    buf->pos = 0;
    buf->size = size;
}

int sbuf_append(struct sbuf *buf, const char *src, size_t src_len)
{
    if ((buf->size - buf->pos) >= src_len) {
        memcpy(buf->ptr + buf->pos, src, src_len);
        buf->pos += src_len;
        return 0;
    }

    return ENOMEM;
}

int sbuf_printf(struct sbuf *buf, const char *fmt, ...)
{
    int n;
    va_list args;

    bug_on(!buf->ptr);

    va_start(args, fmt);
    n = vsnprintf(buf->ptr + buf->pos, buf->size - buf->pos, fmt, args);
    va_end(args);
    if (n < 0)
        return EINVAL;

    if (n < (buf->size - buf->pos)) {
        buf->pos += n;
        return 0;
    }

    return ENOMEM;
}