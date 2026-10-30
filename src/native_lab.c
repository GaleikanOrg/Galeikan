#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GAK_LAB_CASES 256u
#define GAK_LAB_INPUT 1048576u
#define GAK_LAB_MATERIALIZED 67108864u

#define LAB_ERROR(name, message) \
    static const struct { uint64_t length; char bytes[sizeof(message)]; } name = { \
        sizeof(message) - 1, message \
    }

LAB_ERROR(gak_lab_allocation_error, "native allocation failed");
LAB_ERROR(gak_lab_span_error, "mutation span out of bounds");
LAB_ERROR(gak_lab_input_error, "lab.mutate source exceeds 1048576 bytes");
LAB_ERROR(gak_lab_negative_count_error, "mutation count must not be negative");
LAB_ERROR(gak_lab_count_error, "mutation count exceeds 256");
LAB_ERROR(gak_lab_strategy_error, "unknown mutation strategy");
LAB_ERROR(gak_lab_truncate_error, "truncate strategy requires the whole Source");
LAB_ERROR(gak_lab_width_error, "integer-boundary strategy needs a wider selected span");
LAB_ERROR(gak_lab_materialized_error, "mutation corpus exceeds 67108864 materialized bytes");

const uint8_t *gak_lab_error;

typedef struct {
    uint64_t kind; /* 0: view, 1: patch, 2: splice */
    uint64_t offset;
    uint64_t removed;
    uint64_t replacement_length;
    uint64_t replacement;
    uint64_t label_length;
    char label[80];
} GakLabCase;

_Static_assert(sizeof(GakLabCase) == 128, "native mutation case layout changed");

typedef struct {
    uint64_t count;
    GakLabCase cases[GAK_LAB_CASES];
} GakLabPlan;

static GakLabPlan *gak_lab_fail(GakLabPlan *plan, const void *error) {
    free(plan);
    gak_lab_error = error;
    return NULL;
}

static int gak_lab_mode(const uint8_t *box, const char *text) {
    uint64_t length = *(const uint64_t *)box;
    size_t expected = strlen(text);
    return length == expected && memcmp(box + 8, text, expected) == 0;
}

static uint64_t gak_lab_boundaries(unsigned width, unsigned index) {
    uint64_t sign = UINT64_C(1) << (width * 8 - 1);
    uint64_t maximum = width == 8 ? UINT64_MAX : ((UINT64_C(1) << (width * 8)) - 1);
    switch (index) {
        case 0: return 0;
        case 1: return 1;
        case 2: return sign - 1;
        case 3: return sign;
        default: return maximum;
    }
}

static uint64_t gak_lab_encoded(uint64_t value, unsigned width, int little) {
    uint8_t bytes[8] = {0};
    uint64_t encoded = 0;
    for (unsigned index = 0; index < width; ++index) {
        unsigned shift = little ? index : width - index - 1;
        bytes[index] = (uint8_t)(value >> (shift * 8));
    }
    memcpy(&encoded, bytes, width);
    return encoded;
}

static int gak_lab_push(GakLabPlan *plan, uint64_t wanted, uint64_t *materialized,
                        uint64_t candidate_size, uint64_t kind, uint64_t offset,
                        uint64_t removed, uint64_t replacement_length,
                        uint64_t replacement, const char *label) {
    if (plan->count >= wanted) return 0;
    if (candidate_size > GAK_LAB_MATERIALIZED - *materialized) return -1;
    *materialized += candidate_size;
    GakLabCase *item = &plan->cases[plan->count++];
    item->kind = kind;
    item->offset = offset;
    item->removed = removed;
    item->replacement_length = replacement_length;
    item->replacement = replacement;
    item->label_length = strlen(label);
    memcpy(item->label, label, item->label_length);
    return 1;
}

GakLabPlan *gak_native_lab_plan(const uint8_t *source, int64_t start,
                                int64_t span_length, const uint8_t *strategy,
                                int64_t count) {
    gak_lab_error = NULL;
    const uint8_t *backing = *(const uint8_t *const *)source;
    uint64_t view_start = *(const uint64_t *)(source + 16);
    uint64_t view_end = *(const uint64_t *)(source + 24);
    uint64_t source_size = view_end - view_start;
    if (source_size > GAK_LAB_INPUT)
        return gak_lab_fail(NULL, &gak_lab_input_error);
    if (start < 0 || span_length < 0 || (uint64_t)start > source_size ||
        (uint64_t)span_length > source_size - (uint64_t)start)
        return gak_lab_fail(NULL, &gak_lab_span_error);
    if (count < 0) return gak_lab_fail(NULL, &gak_lab_negative_count_error);
    if (count > GAK_LAB_CASES) return gak_lab_fail(NULL, &gak_lab_count_error);

    unsigned mode = 0;
    unsigned width = 0;
    int little = 0;
    if (gak_lab_mode(strategy, "bitflip")) mode = 1;
    else if (gak_lab_mode(strategy, "byte-boundary")) mode = 2;
    else if (gak_lab_mode(strategy, "truncate")) mode = 3;
    else if (gak_lab_mode(strategy, "insert-boundary")) mode = 4;
    else if (gak_lab_mode(strategy, "delete-byte")) mode = 5;
    else {
        static const unsigned widths[] = {2, 4, 8};
        for (unsigned index = 0; index < 3 && !mode; ++index) {
            char name[] = "integer-boundary:u16le";
            name[18] = (char)('0' + widths[index] * 8 / 10);
            name[19] = (char)('0' + widths[index] * 8 % 10);
            if (gak_lab_mode(strategy, name)) { mode = 6; width = widths[index]; little = 1; }
            name[20] = 'b'; name[21] = 'e';
            if (gak_lab_mode(strategy, name)) { mode = 6; width = widths[index]; little = 0; }
        }
    }
    if (!mode) return gak_lab_fail(NULL, &gak_lab_strategy_error);
    uint64_t begin = (uint64_t)start;
    uint64_t end = begin + (uint64_t)span_length;
    if (mode == 3 && (begin != 0 || end != source_size))
        return gak_lab_fail(NULL, &gak_lab_truncate_error);
    if (mode == 6 && end - begin < width)
        return gak_lab_fail(NULL, &gak_lab_width_error);

    GakLabPlan *plan = calloc(1, sizeof(*plan));
    if (!plan) return gak_lab_fail(NULL, &gak_lab_allocation_error);
    const uint8_t *data = backing + 8 + view_start;
    uint64_t wanted = (uint64_t)count;
    uint64_t materialized = 0;
    int pushed;
    char label[80];
    if (mode == 3) {
        for (uint64_t removed = 1; removed <= wanted && removed <= source_size; ++removed) {
            snprintf(label, sizeof(label), " truncate to %llu",
                     (unsigned long long)(source_size - removed));
            (void)gak_lab_push(plan, wanted, &materialized, 0, 0, 0, removed, 0, 0, label);
        }
    } else if (mode == 4) {
        static const uint8_t boundaries[] = {0x00, 0x7f, 0x80, 0xff};
        for (uint64_t offset = begin; offset <= end && plan->count < wanted; ++offset)
            for (unsigned index = 0; index < 4 && plan->count < wanted; ++index) {
                snprintf(label, sizeof(label), " insert-boundary 0x%02x at %llu",
                         boundaries[index], (unsigned long long)offset);
                pushed = gak_lab_push(plan, wanted, &materialized, source_size + 1,
                                      2, offset, 0, 1, boundaries[index], label);
                if (pushed < 0) return gak_lab_fail(plan, &gak_lab_materialized_error);
            }
    } else if (mode == 5) {
        for (uint64_t offset = begin; offset < end && plan->count < wanted; ++offset) {
            snprintf(label, sizeof(label), " delete-byte at %llu", (unsigned long long)offset);
            pushed = gak_lab_push(plan, wanted, &materialized, source_size - 1,
                                  2, offset, 1, 0, 0, label);
            if (pushed < 0) return gak_lab_fail(plan, &gak_lab_materialized_error);
        }
    } else if (mode == 6) {
        for (uint64_t offset = begin; offset <= end - width && plan->count < wanted; ++offset)
            for (unsigned index = 0; index < 5 && plan->count < wanted; ++index) {
                uint64_t boundary = gak_lab_boundaries(width, index);
                uint64_t encoded = gak_lab_encoded(boundary, width, little);
                if (memcmp(data + offset, &encoded, width) == 0) continue;
                snprintf(label, sizeof(label), " integer-boundary u%u%s 0x%llx at %llu",
                         width * 8, little ? "le" : "be", (unsigned long long)boundary,
                         (unsigned long long)offset);
                pushed = gak_lab_push(plan, wanted, &materialized, source_size,
                                      1, offset, width, width, encoded, label);
                if (pushed < 0) return gak_lab_fail(plan, &gak_lab_materialized_error);
            }
    } else {
        static const uint8_t boundaries[] = {0x00, 0x7f, 0x80, 0xff};
        for (uint64_t offset = begin; offset < end && plan->count < wanted; ++offset) {
            if (mode == 1) {
                for (unsigned bit = 0; bit < 8 && plan->count < wanted; ++bit) {
                    uint8_t replacement = data[offset] ^ (uint8_t)(1u << bit);
                    snprintf(label, sizeof(label), " bitflip bit %u at %llu", bit,
                             (unsigned long long)offset);
                    pushed = gak_lab_push(plan, wanted, &materialized, source_size,
                                          1, offset, 1, 1, replacement, label);
                    if (pushed < 0) return gak_lab_fail(plan, &gak_lab_materialized_error);
                }
            } else {
                for (unsigned index = 0; index < 4 && plan->count < wanted; ++index) {
                    if (boundaries[index] == data[offset]) continue;
                    snprintf(label, sizeof(label), " byte-boundary 0x%02x at %llu",
                             boundaries[index], (unsigned long long)offset);
                    pushed = gak_lab_push(plan, wanted, &materialized, source_size,
                                          1, offset, 1, 1, boundaries[index], label);
                    if (pushed < 0) return gak_lab_fail(plan, &gak_lab_materialized_error);
                }
            }
        }
    }
    return plan;
}
