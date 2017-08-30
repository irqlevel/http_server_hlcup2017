#pragma once

#include "base.h"

int utf8_encode(int32_t codepoint, char *buffer, size_t *size);

int ut8_parse_escaped_string(const char *src, size_t src_len, char *dst, size_t dst_len);
