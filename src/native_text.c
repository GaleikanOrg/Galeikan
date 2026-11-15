#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static uint64_t gak_text_size(const uint8_t *box) {
    uint64_t size;
    memcpy(&size, box, sizeof(size));
    return size;
}

/* Returns decoded size, -1 for malformed input, or -2 if it exceeds the
 * bytes value limit. Passing NULL output validates and measures only. */
int64_t gak_native_base64_decode(const uint8_t *box, uint8_t *output,
                                 uint64_t capacity, uint64_t url_safe) {
    uint64_t size = gak_text_size(box);
    const uint8_t *data = box + 8;
    uint8_t quartet[4];
    unsigned count = 0;
    int padded = 0;
    uint64_t written = 0;
    for (uint64_t i = 0; i < size; ++i) {
        uint8_t byte = data[i];
        uint8_t value;
        if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n')
            continue;
        if (padded) return -1;
        if (byte >= 'A' && byte <= 'Z') value = byte - 'A';
        else if (byte >= 'a' && byte <= 'z') value = byte - 'a' + 26;
        else if (byte >= '0' && byte <= '9') value = byte - '0' + 52;
        else if (!url_safe && byte == '+') value = 62;
        else if (!url_safe && byte == '/') value = 63;
        else if (url_safe && byte == '-') value = 62;
        else if (url_safe && byte == '_') value = 63;
        else if (byte == '=') value = 64;
        else return -1;
        quartet[count++] = value;
        if (count == 4) {
            uint8_t a = quartet[0], b = quartet[1];
            uint8_t c = quartet[2], d = quartet[3];
            if (a == 64 || b == 64 ||
                (c == 64 && (d != 64 || (b & 15) != 0)) ||
                (c != 64 && d == 64 && (c & 3) != 0)) return -1;
            uint64_t width = c == 64 ? 1 : d == 64 ? 2 : 3;
            if (written > 1048576u - width) return -2;
            if (output) {
                if (written + width > capacity) return -1;
                output[written] = (a << 2) | (b >> 4);
                if (width > 1) output[written + 1] = (b << 4) | (c >> 2);
                if (width > 2) output[written + 2] = (c << 6) | d;
            }
            written += width;
            padded = width < 3;
            count = 0;
        }
    }
    if (count) {
        if (!url_safe || count == 1 || quartet[0] == 64 || quartet[1] == 64 ||
            (count == 2 && (quartet[1] & 15) != 0) ||
            (count == 3 && (quartet[2] == 64 || (quartet[2] & 3) != 0)))
            return -1;
        uint64_t width = count - 1;
        if (written > 1048576u - width) return -2;
        if (output) {
            if (written + width > capacity) return -1;
            output[written] = (quartet[0] << 2) | (quartet[1] >> 4);
            if (width > 1)
                output[written + 1] = (quartet[1] << 4) | (quartet[2] >> 2);
        }
        written += width;
    }
    return (int64_t)written;
}

/* The caller allocates 4 * ceil(input length / 3) output bytes for the
 * standard alphabet, or floor((4 * input length + 2) / 3) for URL-safe. */
void gak_native_base64_encode(const uint8_t *box, uint8_t *output,
                              uint64_t url_safe) {
    static const uint8_t standard[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const uint8_t url[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const uint8_t *digits = url_safe ? url : standard;
    uint64_t size = gak_text_size(box);
    const uint8_t *data = box + 8;
    uint64_t written = 0;
    for (uint64_t i = 0; i < size; i += 3) {
        uint8_t a = data[i];
        uint8_t b = i + 1 < size ? data[i + 1] : 0;
        uint8_t c = i + 2 < size ? data[i + 2] : 0;
        output[written++] = digits[a >> 2];
        output[written++] = digits[((a & 3) << 4) | (b >> 4)];
        if (i + 1 < size) output[written++] = digits[((b & 15) << 2) | (c >> 6)];
        else if (!url_safe) output[written++] = '=';
        if (i + 2 < size) output[written++] = digits[c & 63];
        else if (!url_safe) output[written++] = '=';
    }
}

static int gak_utf8_valid(const uint8_t *data, uint64_t count) {
    for (uint64_t i = 0; i < count;) {
        uint8_t a = data[i];
        if (a < 0x80) { ++i; continue; }
        uint64_t remaining = count - i;
        if (a >= 0xc2 && a <= 0xdf) {
            if (remaining < 2 || (data[i+1] & 0xc0) != 0x80) return 0;
            i += 2;
        } else if (a >= 0xe0 && a <= 0xef) {
            if (remaining < 3 || (data[i+2] & 0xc0) != 0x80) return 0;
            uint8_t b = data[i+1];
            if ((b & 0xc0) != 0x80 || (a == 0xe0 && b < 0xa0) ||
                (a == 0xed && b >= 0xa0)) return 0;
            i += 3;
        } else if (a >= 0xf0 && a <= 0xf4) {
            if (remaining < 4 || (data[i+2] & 0xc0) != 0x80 ||
                (data[i+3] & 0xc0) != 0x80) return 0;
            uint8_t b = data[i+1];
            if ((b & 0xc0) != 0x80 || (a == 0xf0 && b < 0x90) ||
                (a == 0xf4 && b >= 0x90)) return 0;
            i += 4;
        } else return 0;
    }
    return 1;
}

/* Returns 0 on success, 1 for a range error, 2 for invalid UTF-8. */
int gak_native_read_utf8(const uint8_t *source, uint64_t offset, uint64_t length) {
    const uint8_t *backing;
    uint64_t start, end;
    memcpy(&backing, source, sizeof(backing));
    memcpy(&start, source + 16, sizeof(start));
    memcpy(&end, source + 24, sizeof(end));
    uint64_t size = end - start;
    if (offset > size || length > size - offset) return 1;
    return gak_utf8_valid(backing + 8 + start + offset, length) ? 0 : 2;
}

/* Returns 0 on success, 1 for an invalid offset, 2 for a missing NUL,
 * and 3 for invalid UTF-8. Source is a boxed backing pointer followed by
 * a parent pointer and the visible [start, end) range. */
int gak_native_read_cstring(const uint8_t *source, uint64_t offset,
                            uint64_t max_bytes, uint64_t *length) {
    const uint8_t *backing;
    uint64_t start, end;
    memcpy(&backing, source, sizeof(backing));
    memcpy(&start, source + 16, sizeof(start));
    memcpy(&end, source + 24, sizeof(end));
    uint64_t size = end - start;
    if (offset >= size) return 1;
    uint64_t available = size - offset;
    if (available > max_bytes) available = max_bytes;
    const uint8_t *data = backing + 8 + start + offset;
    const uint8_t *nul = memchr(data, 0, (size_t)available);
    if (!nul) return 2;
    uint64_t count = (uint64_t)(nul - data);
    if (!gak_utf8_valid(data, count)) return 3;
    *length = count;
    return 0;
}

/* max_units stores the byte order in bit 16 (set for big endian). Returns
 * UTF-8 length or -1 offset, -2 unterminated, -3 invalid UTF-16. */
int64_t gak_native_read_wstring(const uint8_t *source, uint64_t offset,
                                uint64_t options, uint8_t *output) {
    const uint8_t *backing;
    uint64_t start, end;
    memcpy(&backing, source, sizeof(backing));
    memcpy(&start, source + 16, sizeof(start));
    memcpy(&end, source + 24, sizeof(end));
    uint64_t size = end - start;
    if (offset >= size) return -1;
    const uint8_t *data = backing + 8 + start + offset;
    uint64_t available = (size - offset) / 2;
    uint64_t max_units = options & 0xffffu;
    if (available > max_units) available = max_units;
    int big_endian = (options & 0x10000u) != 0;
    uint64_t count = 0;
    int terminated = 0;
    for (; count < available; ++count) {
        uint8_t a = data[count * 2], b = data[count * 2 + 1];
        uint16_t unit = big_endian ? ((uint16_t)a << 8) | b
                                   : ((uint16_t)b << 8) | a;
        if (unit == 0) { terminated = 1; break; }
    }
    if (!terminated) return -2;
    uint64_t length = 0;
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t a = data[i * 2], b = data[i * 2 + 1];
        uint32_t codepoint = big_endian ? ((uint16_t)a << 8) | b
                                        : ((uint16_t)b << 8) | a;
        if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            if (++i >= count) return -3;
            a = data[i * 2]; b = data[i * 2 + 1];
            uint32_t low = big_endian ? ((uint16_t)a << 8) | b
                                      : ((uint16_t)b << 8) | a;
            if (low < 0xdc00 || low > 0xdfff) return -3;
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
        } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) return -3;
        if (codepoint < 0x80) {
            if (output) output[length] = (uint8_t)codepoint;
            length += 1;
        } else if (codepoint < 0x800) {
            if (output) {
                output[length] = (uint8_t)(0xc0 | (codepoint >> 6));
                output[length + 1] = (uint8_t)(0x80 | (codepoint & 0x3f));
            }
            length += 2;
        } else if (codepoint < 0x10000) {
            if (output) {
                output[length] = (uint8_t)(0xe0 | (codepoint >> 12));
                output[length + 1] = (uint8_t)(0x80 | ((codepoint >> 6) & 0x3f));
                output[length + 2] = (uint8_t)(0x80 | (codepoint & 0x3f));
            }
            length += 3;
        } else {
            if (output) {
                output[length] = (uint8_t)(0xf0 | (codepoint >> 18));
                output[length + 1] = (uint8_t)(0x80 | ((codepoint >> 12) & 0x3f));
                output[length + 2] = (uint8_t)(0x80 | ((codepoint >> 6) & 0x3f));
                output[length + 3] = (uint8_t)(0x80 | (codepoint & 0x3f));
            }
            length += 4;
        }
    }
    return (int64_t)length;
}

static int gak_text_boundary(const uint8_t *data, uint64_t offset) {
    return offset == 0 || (data[offset] & 0xc0u) != 0x80u;
}

int64_t gak_native_text_length(const uint8_t *box) {
    const uint8_t *data = box + 8;
    uint64_t size = gak_text_size(box);
    int64_t count = 0;
    for (uint64_t offset = 0; offset < size; ++offset) {
        if (gak_text_boundary(data, offset)) ++count;
    }
    return count;
}

static int64_t gak_find_raw(const uint8_t *data, uint64_t size,
                            const uint8_t *needle, uint64_t needle_size) {
    if (needle_size == 0) return 0;
    if (needle_size > size) return -1;
    if (needle_size > SIZE_MAX / sizeof(uint32_t)) return -2;
    uint32_t local_failure[256];
    uint32_t *failure = local_failure;
    if (needle_size > sizeof(local_failure) / sizeof(local_failure[0])) {
        failure = malloc((size_t)needle_size * sizeof(*failure));
        if (!failure) return -2;
    }
    failure[0] = 0;
    uint32_t matched = 0;
    for (uint64_t index = 1; index < needle_size; ++index) {
        while (matched && needle[index] != needle[matched])
            matched = failure[matched - 1];
        if (needle[index] == needle[matched]) ++matched;
        failure[index] = matched;
    }
    matched = 0;
    for (uint64_t index = 0; index < size; ++index) {
        while (matched && data[index] != needle[matched])
            matched = failure[matched - 1];
        if (data[index] == needle[matched]) ++matched;
        if (matched == needle_size) {
            uint64_t offset = index + 1 - needle_size;
            if (failure != local_failure) free(failure);
            return (int64_t)offset;
        }
    }
    if (failure != local_failure) free(failure);
    return -1;
}

int64_t gak_native_bytes_find(const uint8_t *box, const uint8_t *needle_box) {
    return gak_find_raw(box + 8, gak_text_size(box), needle_box + 8,
                        gak_text_size(needle_box));
}

int64_t gak_native_source_find(const uint8_t *source, const uint8_t *needle_box,
                               uint64_t offset) {
    const uint8_t *backing = *(const uint8_t *const *)source;
    uint64_t view_start = *(const uint64_t *)(source + 16);
    uint64_t view_end = *(const uint64_t *)(source + 24);
    uint64_t size = view_end - view_start;
    if (offset > size) return -3;
    int64_t found = gak_find_raw(backing + 8 + view_start + offset, size - offset,
                                 needle_box + 8, gak_text_size(needle_box));
    return found < 0 ? found : found + (int64_t)offset;
}

int64_t gak_native_text_find(const uint8_t *box, const uint8_t *needle_box) {
    int64_t offset = gak_native_bytes_find(box, needle_box);
    if (offset < 0) return offset;
    int64_t character = 0;
    for (int64_t prefix = 0; prefix < offset; ++prefix) {
        if (gak_text_boundary(box + 8, (uint64_t)prefix)) ++character;
    }
    return character;
}

int gak_native_text_starts_with(const uint8_t *box, const uint8_t *prefix_box) {
    uint64_t size = gak_text_size(box);
    uint64_t prefix_size = gak_text_size(prefix_box);
    return prefix_size <= size &&
           memcmp(box + 8, prefix_box + 8, (size_t)prefix_size) == 0;
}

int gak_native_text_ends_with(const uint8_t *box, const uint8_t *suffix_box) {
    uint64_t size = gak_text_size(box);
    uint64_t suffix_size = gak_text_size(suffix_box);
    return suffix_size <= size &&
           memcmp(box + 8 + (size - suffix_size), suffix_box + 8,
                  (size_t)suffix_size) == 0;
}

int gak_native_text_slice_bounds(const uint8_t *box, int64_t start, int64_t count,
                                 uint64_t bounds[2]) {
    if (start < 0 || count < 0) return 0;
    uint64_t first = (uint64_t)start;
    uint64_t end = first + (uint64_t)count;
    const uint8_t *data = box + 8;
    uint64_t size = gak_text_size(box);
    uint64_t character = 0;
    uint64_t first_byte = UINT64_MAX;
    for (uint64_t offset = 0; offset <= size; ++offset) {
        if (offset != size && !gak_text_boundary(data, offset)) continue;
        if (character == first) first_byte = offset;
        if (character == end) {
            if (first_byte == UINT64_MAX) return 0;
            bounds[0] = first_byte;
            bounds[1] = offset - first_byte;
            return 1;
        }
        ++character;
    }
    return 0;
}
