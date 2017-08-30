#include "utf.h"
#include "misc.h"

int32_t utf8_parse_escaped_codepoint(const char *s, size_t len)
{
    int r;
    uint32_t result;

    if (len != 6)
        return -1;

    if (s[0] != '\\' || s[1] != 'u')
        return -1;

    r = hex_string_to_uint32(&s[2], 4, &result);
    if (r)
        return -1;

    return result;
}

static size_t min(size_t a, size_t b)
{
    if (a < b)
        return a;
    return b;
}

int ut8_parse_escaped_string(const char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t i, j, dst_pos;
    int32_t codepoint;
    char buffer[4];
    size_t buffer_size;

    dst_pos = 0;
    for (i = 0; i < src_len; i++) {
        codepoint = utf8_parse_escaped_codepoint(&src[i], min(src_len - i, 6));
        if (codepoint < 0) {
            if (dst_pos >= dst_len)
                return -1;

            dst[dst_pos++] = src[i];
        } else {
            if (utf8_encode(codepoint, buffer, &buffer_size) < 0)
                return -1;
            
            for (j = 0; j < buffer_size; j++) {
                if (dst_pos >= dst_len)
                    return -1;

                dst[dst_pos++] = buffer[j];
            }
            i+= 5;
        }
    }

    return dst_pos;
}

int utf8_encode(int32_t codepoint, char *buffer, size_t *size)
{
    if(codepoint < 0)
    {
        return -1;
    }
    else if(codepoint < 0x80)
    {
        buffer[0] = (char)codepoint;
        *size = 1;
    }
    else if(codepoint < 0x800)
    {
        buffer[0] = 0xC0 + ((codepoint & 0x7C0) >> 6);
        buffer[1] = 0x80 + ((codepoint & 0x03F));
        *size = 2;
    }
    else if(codepoint < 0x10000)
    {
        buffer[0] = 0xE0 + ((codepoint & 0xF000) >> 12);
        buffer[1] = 0x80 + ((codepoint & 0x0FC0) >> 6);
        buffer[2] = 0x80 + ((codepoint & 0x003F));
        *size = 3;
    }
    else if(codepoint <= 0x10FFFF)
    {
        buffer[0] = 0xF0 + ((codepoint & 0x1C0000) >> 18);
        buffer[1] = 0x80 + ((codepoint & 0x03F000) >> 12);
        buffer[2] = 0x80 + ((codepoint & 0x000FC0) >> 6);
        buffer[3] = 0x80 + ((codepoint & 0x00003F));
        *size = 4;
    }
    else
    {
        return -1;
    }

    return 0;
}
