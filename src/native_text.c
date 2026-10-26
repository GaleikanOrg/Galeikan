#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static uint64_t gak_text_size(const uint8_t *box) {
    uint64_t size;
    memcpy(&size, box, sizeof(size));
    return size;
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

int64_t gak_native_text_find(const uint8_t *box, const uint8_t *needle_box) {
    const uint8_t *data = box + 8;
    const uint8_t *needle = needle_box + 8;
    uint64_t size = gak_text_size(box);
    uint64_t needle_size = gak_text_size(needle_box);
    if (needle_size == 0) return 0;
    if (needle_size > size) return -1;
    if (needle_size > SIZE_MAX / sizeof(uint32_t)) return -2;
    uint32_t *failure = malloc((size_t)needle_size * sizeof(*failure));
    if (!failure) return -2;
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
            free(failure);
            int64_t character = 0;
            for (uint64_t prefix = 0; prefix < offset; ++prefix) {
                if (gak_text_boundary(data, prefix)) ++character;
            }
            return character;
        }
    }
    free(failure);
    return -1;
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
