#include "native_asm_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef GALEIKAN_ASM_FORMATS
extern int gak_native_formats_x86_instruction_range(const void *format,
                                                     uint64_t ip, uint64_t size,
                                                     uint64_t file_start);
extern uint8_t *gak_formats_error;
#endif

/* Source layout is shared with generated native programs. */
typedef struct {
    const uint8_t *backing;
    const void *parent;
    uint64_t start;
    uint64_t end;
} GakSourceHead;

typedef struct GakAsmInstruction {
    struct GakAsmInstruction *next_owned;
    const GakSourceHead *source;
    uint64_t offset;
    void *decoded;
    uint64_t address_kind;
    uint64_t address;
} GakAsmInstruction;

typedef struct GakAsmDisassembly {
    struct GakAsmDisassembly *next_owned;
    const GakSourceHead *source;
    uint64_t start_offset;
    void *decoded;
    uint64_t offset_bias;
    uint64_t address_kind;
    const GakSourceHead *display_source;
    uint64_t range_start;
    uint64_t range_end;
} GakAsmDisassembly;

static struct {
    uint64_t length;
    char text[256];
} error_box;
uint8_t *gak_asm_error;
static GakAsmInstruction *owned_instructions;
static GakAsmDisassembly *owned_disassemblies;
static int exit_handler_registered;
static size_t instruction_count;
static size_t disassembly_instruction_count;
static size_t boxed_text_bytes;
static size_t boxed_list_bytes;
static void gak_asm_fail(const char *message);

const GakSourceHead *gak_native_asm_parent_source(const GakAsmInstruction *instruction) {
    gak_asm_error = NULL;
    if (!instruction || !instruction->source) {
        gak_asm_fail("invalid Instruction");
        return NULL;
    }
    return instruction->source;
}

static void gak_asm_release_all(void) {
    while (owned_instructions) {
        GakAsmInstruction *next = owned_instructions->next_owned;
        galeikan_asm_instruction_free(owned_instructions->decoded);
        free(owned_instructions);
        owned_instructions = next;
    }
    while (owned_disassemblies) {
        GakAsmDisassembly *next = owned_disassemblies->next_owned;
        galeikan_asm_disassembly_free(owned_disassemblies->decoded);
        free(owned_disassemblies);
        owned_disassemblies = next;
    }
}

static void gak_asm_fail(const char *message) {
    size_t length = strlen(message);
    if (length > sizeof error_box.text) length = sizeof error_box.text;
    error_box.length = length;
    memcpy(error_box.text, message, length);
    gak_asm_error = (uint8_t *)&error_box;
}

static uint8_t *gak_asm_box_text(const uint8_t *bytes, size_t length) {
    if (length > 4096) {
        gak_asm_fail("instruction text exceeds native limit");
        return NULL;
    }
    if (boxed_text_bytes > 64u * 1024u * 1024u - sizeof(uint64_t) - length) {
        gak_asm_fail("native instruction text memory exceeds 64 MiB");
        return NULL;
    }
    uint8_t *box = malloc(length + sizeof(uint64_t));
    if (!box) {
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    uint64_t wide_length = (uint64_t)length;
    memcpy(box, &wide_length, sizeof wide_length);
    if (length && bytes) memcpy(box + sizeof wide_length, bytes, length);
    boxed_text_bytes += length + sizeof wide_length;
    return box;
}

static uint64_t *gak_asm_box_u64_list(size_t count) {
    if (count > 10000 || boxed_list_bytes > 64u * 1024u * 1024u -
        (count + 1) * sizeof(uint64_t)) {
        gak_asm_fail("native Disassembly list memory exceeds 64 MiB");
        return NULL;
    }
    size_t size = (count + 1) * sizeof(uint64_t);
    uint64_t *box = malloc(size);
    if (!box) {
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    box[0] = (uint64_t)count;
    boxed_list_bytes += size;
    return box;
}

static int gak_asm_bounds(void *decoded, uint64_t bias,
                          uint64_t *start, uint64_t *end) {
    size_t relative_start = 0, relative_end = 0;
    if (!galeikan_asm_disassembly_bounds(decoded, &relative_start, &relative_end) ||
        bias > UINT64_MAX - relative_end) {
        gak_asm_fail("invalid Disassembly instruction range");
        return 0;
    }
    *start = bias + relative_start;
    *end = bias + relative_end;
    return 1;
}

GakAsmInstruction *gak_native_asm_decode(const GakSourceHead *source,
                                          int64_t offset, uint64_t ip,
                                          int64_t bitness) {
    gak_asm_error = NULL;
    if (!source || !source->backing || source->end < source->start ||
        source->end > *(const uint64_t *)source->backing) {
        gak_asm_fail("invalid Source for x86 decoder");
        return NULL;
    }
    if (offset < 0) {
        gak_asm_fail("instruction offset must be nonnegative");
        return NULL;
    }
    if (bitness != 16 && bitness != 32 && bitness != 64) {
        gak_asm_fail("x86 bitness must be 16, 32, or 64");
        return NULL;
    }
    if (instruction_count >= 100000) {
        gak_asm_fail("native Instruction count exceeds 100000");
        return NULL;
    }
    uint64_t length = source->end - source->start;
    if ((uint64_t)offset >= length) {
        gak_asm_fail("instruction offset out of bounds");
        return NULL;
    }
    const uint8_t *bytes = source->backing + sizeof(uint64_t) + source->start;
    uint8_t error[256] = {0};
    void *decoded = NULL;
    if (galeikan_asm_decode(bytes, (size_t)length, (size_t)offset, ip,
                            (uint32_t)bitness, &decoded, error, sizeof error)) {
        gak_asm_fail((const char *)error);
        return NULL;
    }
    GakAsmInstruction *instruction = malloc(sizeof *instruction);
    if (!instruction) {
        galeikan_asm_instruction_free(decoded);
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    if (!exit_handler_registered) {
        if (atexit(gak_asm_release_all)) {
            free(instruction);
            galeikan_asm_instruction_free(decoded);
            gak_asm_fail("cannot register decoder cleanup");
            return NULL;
        }
        exit_handler_registered = 1;
    }
    instruction->source = source;
    instruction->offset = (uint64_t)offset;
    instruction->decoded = decoded;
    instruction->address_kind = 0;
    instruction->address = 0;
    instruction->next_owned = owned_instructions;
    owned_instructions = instruction;
    instruction_count++;
    return instruction;
}

/* info comes from gak_native_formats_x86_entry_info. */
GakAsmInstruction *gak_native_asm_entry(const uint64_t info[6]) {
    gak_asm_error = NULL;
    if (!info) { gak_asm_fail("invalid x86 entry window"); return NULL; }
    const GakSourceHead *source = (const GakSourceHead *)(uintptr_t)info[0];
    if (!source || !source->backing || source->end < source->start ||
        source->end > *(const uint64_t *)source->backing ||
        info[1] >= info[2] || info[2] > source->end - source->start ||
        (info[3] != 32 && info[3] != 64) || (info[5] != 1 && info[5] != 2)) {
        gak_asm_fail("invalid x86 entry window"); return NULL;
    }
    if (instruction_count >= 100000) {
        gak_asm_fail("native Instruction count exceeds 100000"); return NULL;
    }
    const uint8_t *bytes = source->backing + sizeof(uint64_t) + source->start + info[1];
    uint8_t error[256] = {0};
    void *decoded = NULL;
    if (galeikan_asm_decode(bytes, (size_t)(info[2] - info[1]), 0, info[4],
                            (uint32_t)info[3], &decoded, error, sizeof error)) {
        gak_asm_fail((const char *)error); return NULL;
    }
    GakAsmInstruction *instruction = malloc(sizeof *instruction);
    if (!instruction) {
        galeikan_asm_instruction_free(decoded);
        gak_asm_fail("native allocation failed"); return NULL;
    }
    if (!exit_handler_registered) {
        if (atexit(gak_asm_release_all)) {
            free(instruction);
            galeikan_asm_instruction_free(decoded);
            gak_asm_fail("cannot register decoder cleanup"); return NULL;
        }
        exit_handler_registered = 1;
    }
    instruction->source = source;
    instruction->offset = info[1];
    instruction->decoded = decoded;
    instruction->address_kind = info[5];
    instruction->address = info[4];
    instruction->next_owned = owned_instructions;
    owned_instructions = instruction;
    instruction_count++;
    return instruction;
}

static GakAsmDisassembly *gak_native_asm_reachable_mode(const GakSourceHead *source,
                                                        int64_t offset, uint64_t base_ip,
                                                        int64_t bitness, int64_t max_instructions,
                                                        int function_only) {
    gak_asm_error = NULL;
    if (!source || !source->backing || source->end < source->start ||
        source->end > *(const uint64_t *)source->backing) {
        gak_asm_fail("invalid Source for x86 decoder");
        return NULL;
    }
    if (offset < 0) {
        gak_asm_fail("reachable entry offset must be nonnegative");
        return NULL;
    }
    if (bitness != 16 && bitness != 32 && bitness != 64) {
        gak_asm_fail("x86 bitness must be 16, 32, or 64");
        return NULL;
    }
    if (max_instructions < 1 || max_instructions > 10000) {
        gak_asm_fail("instruction count must be between 1 and 10000");
        return NULL;
    }
    uint64_t length = source->end - source->start;
    if ((uint64_t)offset >= length) {
        gak_asm_fail("reachable entry offset out of bounds");
        return NULL;
    }
    const uint8_t *bytes = source->backing + sizeof(uint64_t) + source->start;
    uint8_t error[256] = {0};
    void *decoded = NULL;
    int failed = function_only
        ? galeikan_asm_function_reachable(bytes, (size_t)length, (size_t)offset, base_ip,
                                          (uint32_t)bitness, (size_t)max_instructions,
                                          &decoded, error, sizeof error)
        : galeikan_asm_reachable(bytes, (size_t)length, (size_t)offset, base_ip,
                                 (uint32_t)bitness, (size_t)max_instructions,
                                 &decoded, error, sizeof error);
    if (failed) {
        gak_asm_fail((const char *)error);
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_count(decoded);
    if (count > 100000 - disassembly_instruction_count) {
        galeikan_asm_disassembly_free(decoded);
        gak_asm_fail("native Disassembly instruction count exceeds 100000");
        return NULL;
    }
    uint64_t range_start = 0, range_end = 0;
    if (!gak_asm_bounds(decoded, 0, &range_start, &range_end)) {
        galeikan_asm_disassembly_free(decoded);
        return NULL;
    }
    GakAsmDisassembly *disassembly = malloc(sizeof *disassembly);
    if (!disassembly) {
        galeikan_asm_disassembly_free(decoded);
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    if (!exit_handler_registered) {
        if (atexit(gak_asm_release_all)) {
            free(disassembly);
            galeikan_asm_disassembly_free(decoded);
            gak_asm_fail("cannot register decoder cleanup");
            return NULL;
        }
        exit_handler_registered = 1;
    }
    disassembly->source = source;
    disassembly->start_offset = (uint64_t)offset;
    disassembly->decoded = decoded;
    disassembly->offset_bias = 0;
    disassembly->address_kind = 0;
    disassembly->display_source = source;
    disassembly->range_start = range_start;
    disassembly->range_end = range_end;
    disassembly->next_owned = owned_disassemblies;
    owned_disassemblies = disassembly;
    disassembly_instruction_count += count;
    return disassembly;
}

GakAsmDisassembly *gak_native_asm_reachable(const GakSourceHead *source,
                                             int64_t offset, uint64_t base_ip,
                                             int64_t bitness, int64_t max_instructions) {
    return gak_native_asm_reachable_mode(source, offset, base_ip, bitness, max_instructions, 0);
}

GakAsmDisassembly *gak_native_asm_function_reachable(const GakSourceHead *source,
                                                      int64_t offset, uint64_t base_ip,
                                                      int64_t bitness, int64_t max_instructions) {
    return gak_native_asm_reachable_mode(source, offset, base_ip, bitness, max_instructions, 1);
}

uint64_t *gak_native_asm_ret_gadget_starts(const GakSourceHead *source,
                                            int64_t bitness, int64_t max_instructions) {
    gak_asm_error = NULL;
    if (!source || !source->backing || source->end < source->start ||
        source->end > *(const uint64_t *)source->backing) {
        gak_asm_fail("invalid Source for x86 decoder");
        return NULL;
    }
    if (bitness != 16 && bitness != 32 && bitness != 64) {
        gak_asm_fail("x86 bitness must be 16, 32, or 64");
        return NULL;
    }
    if (max_instructions < 1 || max_instructions > 8) {
        gak_asm_fail("gadget instruction count must be between 1 and 8");
        return NULL;
    }
    uint64_t length = source->end - source->start;
    if (length > 1048576) {
        gak_asm_fail("gadget scan exceeds 1048576 bytes");
        return NULL;
    }
    uint64_t *scratch = malloc(10000 * sizeof(uint64_t));
    if (!scratch) {
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    size_t count = 0;
    uint8_t error[256] = {0};
    const uint8_t *bytes = source->backing + sizeof(uint64_t) + source->start;
    int32_t status = galeikan_asm_ret_gadget_starts(bytes, (size_t)length,
        (uint32_t)bitness, (size_t)max_instructions,
        scratch, 10000, &count, error, sizeof error);
    if (status) {
        free(scratch);
        gak_asm_fail(error[0] ? (const char *)error : "x86 gadget scan failed");
        return NULL;
    }
    uint64_t *result = gak_asm_box_u64_list(count);
    if (result) memcpy(result + 1, scratch, count * sizeof(uint64_t));
    free(scratch);
    return result;
}

#ifdef GALEIKAN_ASM_FORMATS
static GakAsmDisassembly *gak_native_asm_entry_disassembly(const uint64_t info[7],
                                                            int64_t count, int mode) {
    gak_asm_error = NULL;
    if (!info) { gak_asm_fail("invalid x86 entry region"); return NULL; }
    const GakSourceHead *source = (const GakSourceHead *)(uintptr_t)info[0];
    if (!source || !source->backing || source->end < source->start ||
        source->end > *(const uint64_t *)source->backing ||
        info[1] >= info[2] || info[2] > source->end - source->start ||
        (info[3] != 32 && info[3] != 64) || (info[5] != 1 && info[5] != 2) || !info[6]) {
        gak_asm_fail("invalid x86 entry region"); return NULL;
    }
    if (count < 1 || count > 10000) {
        gak_asm_fail("instruction count must be between 1 and 10000"); return NULL;
    }
    const uint8_t *bytes = source->backing + sizeof(uint64_t) + source->start + info[1];
    size_t length = (size_t)(info[2] - info[1]);
    uint8_t error[256] = {0};
    void *decoded = NULL;
    int failed = mode == 1
        ? galeikan_asm_linear(bytes, length, info[4], (uint32_t)info[3],
                              (size_t)count, &decoded, error, sizeof error)
        : mode == 2
        ? galeikan_asm_function_reachable(bytes, length, 0, info[4], (uint32_t)info[3],
                                          (size_t)count, &decoded, error, sizeof error)
        : galeikan_asm_reachable(bytes, length, 0, info[4], (uint32_t)info[3],
                                 (size_t)count, &decoded, error, sizeof error);
    if (failed) { gak_asm_fail((const char *)error); return NULL; }
    size_t found = galeikan_asm_disassembly_count(decoded);
    if (found > 100000 - disassembly_instruction_count) {
        galeikan_asm_disassembly_free(decoded);
        gak_asm_fail("native Disassembly instruction count exceeds 100000");
        return NULL;
    }
    for (size_t index = 0; index < found; index++) {
        void *instruction = NULL;
        size_t relative = 0;
        if (!galeikan_asm_disassembly_at(decoded, index, &instruction, &relative)) {
            galeikan_asm_disassembly_free(decoded);
            gak_asm_fail("cannot read decoded entry instruction"); return NULL;
        }
        uint64_t size = galeikan_asm_instruction_size(instruction);
        uint64_t ip = galeikan_asm_instruction_ip(instruction);
        galeikan_asm_instruction_free(instruction);
        if (relative > length || size > length - relative ||
            !gak_native_formats_x86_instruction_range((const void *)(uintptr_t)info[6],
                                                       ip, size, info[1] + relative)) {
            galeikan_asm_disassembly_free(decoded);
            if (gak_formats_error) gak_asm_error = gak_formats_error;
            else gak_asm_fail("instruction bytes do not map to the expected file range");
            return NULL;
        }
    }
    uint64_t range_start = 0, range_end = 0;
    if (!gak_asm_bounds(decoded, info[1], &range_start, &range_end)) {
        galeikan_asm_disassembly_free(decoded);
        return NULL;
    }
    GakAsmDisassembly *disassembly = malloc(sizeof *disassembly);
    if (!disassembly) {
        galeikan_asm_disassembly_free(decoded);
        gak_asm_fail("native allocation failed"); return NULL;
    }
    if (!exit_handler_registered) {
        if (atexit(gak_asm_release_all)) {
            free(disassembly);
            galeikan_asm_disassembly_free(decoded);
            gak_asm_fail("cannot register decoder cleanup"); return NULL;
        }
        exit_handler_registered = 1;
    }
    disassembly->source = source;
    disassembly->start_offset = info[1];
    disassembly->decoded = decoded;
    disassembly->offset_bias = info[1];
    disassembly->address_kind = info[5];
    disassembly->display_source = source;
    disassembly->range_start = range_start;
    disassembly->range_end = range_end;
    disassembly->next_owned = owned_disassemblies;
    owned_disassemblies = disassembly;
    disassembly_instruction_count += found;
    return disassembly;
}

GakAsmDisassembly *gak_native_asm_linear_entry(const uint64_t info[7], int64_t count) {
    return gak_native_asm_entry_disassembly(info, count, 1);
}

GakAsmDisassembly *gak_native_asm_reachable_entry(const uint64_t info[7], int64_t count) {
    return gak_native_asm_entry_disassembly(info, count, 0);
}

GakAsmDisassembly *gak_native_asm_function_entry(const uint64_t info[7], int64_t count) {
    return gak_native_asm_entry_disassembly(info, count, 2);
}
#endif

uint64_t gak_native_asm_disassembly_count(const GakAsmDisassembly *disassembly) {
    gak_asm_error = NULL;
    if (!disassembly) {
        gak_asm_fail("invalid Disassembly");
        return 0;
    }
    return galeikan_asm_disassembly_count(disassembly->decoded);
}

const GakSourceHead *gak_native_asm_disassembly_source(const GakAsmDisassembly *disassembly) {
    gak_asm_error = NULL;
    if (!disassembly || !disassembly->display_source) {
        gak_asm_fail("invalid Disassembly Source");
        return NULL;
    }
    return disassembly->display_source;
}

const GakSourceHead *gak_native_asm_instruction_source(const GakAsmInstruction *instruction) {
    gak_asm_error = NULL;
    if (!instruction || !instruction->source) {
        gak_asm_fail("invalid Instruction Source");
        return NULL;
    }
    return instruction->source;
}

uint64_t gak_native_asm_linear_end(const GakAsmDisassembly *disassembly) {
    gak_asm_error = NULL;
    if (!disassembly) {
        gak_asm_fail("invalid Disassembly");
        return 0;
    }
    return disassembly->range_end;
}

void gak_native_asm_set_display_source(GakAsmDisassembly *disassembly,
                                        const GakSourceHead *source) {
    if (disassembly) disassembly->display_source = source;
}

GakAsmInstruction *gak_native_asm_at(const GakAsmDisassembly *disassembly,
                                      int64_t index) {
    gak_asm_error = NULL;
    if (!disassembly || index < 0 || (uint64_t)index >=
        galeikan_asm_disassembly_count(disassembly->decoded)) {
        gak_asm_fail("instruction index out of range");
        return NULL;
    }
    if (instruction_count >= 100000) {
        gak_asm_fail("native Instruction count exceeds 100000");
        return NULL;
    }
    void *decoded = NULL;
    size_t offset = 0;
    if (!galeikan_asm_disassembly_at(disassembly->decoded, (size_t)index,
                                     &decoded, &offset)) {
        gak_asm_fail("instruction index out of range");
        return NULL;
    }
    GakAsmInstruction *instruction = malloc(sizeof *instruction);
    if (!instruction) {
        galeikan_asm_instruction_free(decoded);
        gak_asm_fail("native allocation failed");
        return NULL;
    }
    instruction->source = disassembly->source;
    instruction->offset = (uint64_t)offset + disassembly->offset_bias;
    instruction->decoded = decoded;
    instruction->address_kind = disassembly->address_kind;
    instruction->address = disassembly->address_kind
        ? galeikan_asm_instruction_ip(decoded) : 0;
    instruction->next_owned = owned_instructions;
    owned_instructions = instruction;
    instruction_count++;
    return instruction;
}

GakAsmInstruction *gak_native_asm_block_instruction(
    const GakAsmDisassembly *disassembly, int64_t block_index, int64_t within) {
    gak_asm_error = NULL;
    GaleikanAsmBlock block;
    if (!disassembly || block_index < 0 ||
        !galeikan_asm_disassembly_block(disassembly->decoded, (size_t)block_index, &block)) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    if (within < 0 || (uint64_t)within >= block.instruction_count) {
        gak_asm_fail("block instruction index out of range");
        return NULL;
    }
    return gak_native_asm_at(disassembly, (int64_t)(block.first_index + (size_t)within));
}

uint64_t gak_native_asm_disassembly_number(const GakAsmDisassembly *disassembly,
                                             int64_t index, uint32_t kind) {
    gak_asm_error = NULL;
    if (!disassembly) {
        gak_asm_fail("invalid Disassembly");
        return 0;
    }
    if (kind == 1) return galeikan_asm_disassembly_count(disassembly->decoded);
    if (kind == 2) return galeikan_asm_disassembly_block_count(disassembly->decoded);
    if (kind == 3) return galeikan_asm_disassembly_overlap_count(disassembly->decoded);
    if (kind == 9) return disassembly->range_start;
    if (kind == 10) return disassembly->range_end;
    if (index < 0) {
        gak_asm_fail(kind == 4 ? "instruction index out of range" : "block index out of range");
        return 0;
    }
    if (kind == 4) {
        int32_t overlap = 0;
        if (galeikan_asm_disassembly_overlap_at(disassembly->decoded, (size_t)index, &overlap))
            return (uint64_t)overlap;
        gak_asm_fail("instruction index out of range");
        return 0;
    }
    GaleikanAsmBlock block;
    if (!galeikan_asm_disassembly_block(disassembly->decoded, (size_t)index, &block)) {
        gak_asm_fail("block index out of range");
        return 0;
    }
    switch (kind) {
        case 5: return block.start;
        case 6: return block.end;
        case 7: return block.instruction_count;
        case 8: return (uint64_t)block.unresolved;
        default:
            gak_asm_fail("unknown Disassembly numeric field");
            return 0;
    }
}

uint64_t *gak_native_asm_instruction_successors(const GakAsmInstruction *instruction) {
    gak_asm_error = NULL;
    if (!instruction) {
        gak_asm_fail("invalid Instruction");
        return NULL;
    }
    size_t count = galeikan_asm_instruction_successors_count(instruction->decoded);
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    for (size_t index = 0; index < count; index++) {
        if (!galeikan_asm_instruction_successor(instruction->decoded, index, &result[index + 1])) {
            gak_asm_fail("cannot read instruction successor");
            return NULL;
        }
    }
    return result;
}

uint64_t *gak_native_asm_block_successors(const GakAsmDisassembly *disassembly,
                                           int64_t index) {
    gak_asm_error = NULL;
    GaleikanAsmBlock block;
    if (!disassembly || index < 0 ||
        !galeikan_asm_disassembly_block(disassembly->decoded, (size_t)index, &block)) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    uint64_t *result = gak_asm_box_u64_list(block.successor_count);
    if (!result) return NULL;
    for (size_t successor = 0; successor < block.successor_count; successor++) {
        if (!galeikan_asm_disassembly_block_successor(disassembly->decoded, (size_t)index,
                                                      successor, &result[successor + 1])) {
            gak_asm_fail("cannot read block successor");
            return NULL;
        }
    }
    return result;
}

uint64_t *gak_native_asm_block_path(const GakAsmDisassembly *disassembly,
                                    int64_t from, int64_t to) {
    gak_asm_error = NULL;
    if (!disassembly || from < 0 || to < 0) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_block_path(disassembly->decoded,
                                                        (size_t)from, (size_t)to,
                                                        NULL, 0);
    if (count == SIZE_MAX) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    if (galeikan_asm_disassembly_block_path(disassembly->decoded,
                                            (size_t)from, (size_t)to,
                                            result + 1, count) != count) {
        boxed_list_bytes -= (count + 1) * sizeof(uint64_t);
        free(result);
        gak_asm_fail("cannot read block path");
        return NULL;
    }
    return result;
}

uint64_t *gak_native_asm_block_dominators(const GakAsmDisassembly *disassembly,
                                          int64_t entry, int64_t target) {
    gak_asm_error = NULL;
    if (!disassembly || entry < 0 || target < 0) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_block_dominators(disassembly->decoded,
                                                               (size_t)entry, (size_t)target,
                                                               NULL, 0);
    if (count == SIZE_MAX) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    if (galeikan_asm_disassembly_block_dominators(disassembly->decoded,
                                                   (size_t)entry, (size_t)target,
                                                   result + 1, count) != count) {
        boxed_list_bytes -= (count + 1) * sizeof(uint64_t);
        free(result);
        gak_asm_fail("cannot read block dominators");
        return NULL;
    }
    return result;
}

uint64_t *gak_native_asm_block_natural_loop(const GakAsmDisassembly *disassembly,
                                            int64_t entry, int64_t header, int64_t latch) {
    gak_asm_error = NULL;
    if (!disassembly || entry < 0 || header < 0 || latch < 0) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_block_natural_loop(disassembly->decoded,
                                                                 (size_t)entry, (size_t)header,
                                                                 (size_t)latch, NULL, 0);
    if (count == SIZE_MAX) {
        gak_asm_fail("block index out of range");
        return NULL;
    }
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    if (galeikan_asm_disassembly_block_natural_loop(disassembly->decoded,
                                                     (size_t)entry, (size_t)header,
                                                     (size_t)latch, result + 1, count) != count) {
        boxed_list_bytes -= (count + 1) * sizeof(uint64_t);
        free(result);
        gak_asm_fail("cannot read natural loop body");
        return NULL;
    }
    return result;
}

uint64_t *gak_native_asm_references(const GakAsmDisassembly *disassembly,
                                     uint32_t kind, uint64_t target) {
    gak_asm_error = NULL;
    if (!disassembly || kind < 1 || kind > 4) {
        gak_asm_fail("invalid Disassembly reference query");
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_references(disassembly->decoded, kind,
                                                       target, NULL, 0);
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    if (galeikan_asm_disassembly_references(disassembly->decoded, kind, target,
                                            result + 1, count) != count) {
        gak_asm_fail("cannot read Disassembly references");
        return NULL;
    }
    return result;
}

uint64_t *gak_native_asm_names(const GakAsmInstruction *instruction, uint32_t kind) {
    gak_asm_error = NULL;
    if (!instruction) {
        gak_asm_fail("invalid Instruction");
        return NULL;
    }
    size_t (*count_fn)(const void *) = NULL;
    size_t (*get_fn)(const void *, size_t, uint8_t *, size_t) = NULL;
    switch (kind) {
        case 1:
            count_fn = galeikan_asm_instruction_register_reads_count;
            get_fn = galeikan_asm_instruction_register_read;
            break;
        case 2:
            count_fn = galeikan_asm_instruction_register_writes_count;
            get_fn = galeikan_asm_instruction_register_write;
            break;
        case 3:
            count_fn = galeikan_asm_instruction_flags_read_count;
            get_fn = galeikan_asm_instruction_flag_read;
            break;
        case 4:
            count_fn = galeikan_asm_instruction_flags_modified_count;
            get_fn = galeikan_asm_instruction_flag_modified;
            break;
        default:
            gak_asm_fail("unknown Instruction name list");
            return NULL;
    }
    size_t count = count_fn(instruction->decoded);
    uint64_t *result = gak_asm_box_u64_list(count);
    if (!result) return NULL;
    for (size_t index = 0; index < count; index++) {
        size_t length = get_fn(instruction->decoded, index, NULL, 0);
        uint8_t *text = gak_asm_box_text(NULL, length);
        if (!text) return NULL;
        if (get_fn(instruction->decoded, index, text + sizeof(uint64_t), length) != length) {
            gak_asm_fail("cannot read Instruction name");
            return NULL;
        }
        result[index + 1] = (uint64_t)(uintptr_t)text;
    }
    return result;
}

uint8_t *gak_native_asm_text(const GakAsmInstruction *instruction, uint32_t kind) {
    gak_asm_error = NULL;
    if (!instruction) {
        gak_asm_fail("invalid Instruction");
        return NULL;
    }
    size_t (*reader)(const void *, uint8_t *, size_t) = NULL;
    switch (kind) {
        case 1: reader = galeikan_asm_instruction_text; break;
        case 2: reader = galeikan_asm_instruction_mnemonic; break;
        case 3: reader = galeikan_asm_instruction_flow; break;
        case 4:
        case 5: {
            uint64_t address = galeikan_asm_instruction_ip(instruction->decoded);
            if (kind == 5 && !galeikan_asm_instruction_target(instruction->decoded, &address)) {
                gak_asm_fail("instruction has no direct branch target");
                return NULL;
            }
            char formatted[19];
            int count = snprintf(formatted, sizeof formatted, "0x%llx",
                                 (unsigned long long)address);
            if (count < 0 || (size_t)count >= sizeof formatted) {
                gak_asm_fail("cannot format instruction address");
                return NULL;
            }
            return gak_asm_box_text((const uint8_t *)formatted, (size_t)count);
        }
        default:
            gak_asm_fail("unknown instruction text field");
            return NULL;
    }
    size_t length = reader(instruction->decoded, NULL, 0);
    uint8_t *box = gak_asm_box_text(NULL, length);
    if (!box) return NULL;
    if (reader(instruction->decoded, box + sizeof(uint64_t), length) != length) {
        free(box);
        gak_asm_fail("cannot copy instruction text");
        return NULL;
    }
    return box;
}

uint8_t *gak_native_asm_display(const GakAsmInstruction *instruction) {
    gak_asm_error = NULL;
    if (!instruction) {
        gak_asm_fail("invalid Instruction");
        return NULL;
    }
    size_t size = galeikan_asm_instruction_size(instruction->decoded);
    const uint8_t *bytes = instruction->source->backing + sizeof(uint64_t) +
                           instruction->source->start + instruction->offset;
    uint8_t digest[32];
    if (galeikan_asm_sha256(bytes, size, digest)) {
        gak_asm_fail("cannot hash instruction source");
        return NULL;
    }
    uint8_t rendered[4608];
    int prefix = snprintf((char *)rendered, sizeof rendered, "instruction(0x%llx: ",
                          (unsigned long long)galeikan_asm_instruction_ip(instruction->decoded));
    if (prefix < 0 || (size_t)prefix >= sizeof rendered) {
        gak_asm_fail("cannot format Instruction");
        return NULL;
    }
    size_t text_length = galeikan_asm_instruction_text(instruction->decoded, NULL, 0);
    const char suffix[] = ", source_sha256:";
    size_t needed = (size_t)prefix + text_length + sizeof suffix - 1 + 64 + 1;
    if (text_length > 4096 || needed > sizeof rendered) {
        gak_asm_fail("instruction text exceeds native limit");
        return NULL;
    }
    size_t cursor = (size_t)prefix;
    galeikan_asm_instruction_text(instruction->decoded, rendered + cursor, text_length);
    cursor += text_length;
    memcpy(rendered + cursor, suffix, sizeof suffix - 1);
    cursor += sizeof suffix - 1;
    const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < sizeof digest; index++) {
        rendered[cursor++] = (uint8_t)digits[digest[index] >> 4];
        rendered[cursor++] = (uint8_t)digits[digest[index] & 15];
    }
    rendered[cursor++] = ')';
    return gak_asm_box_text(rendered, cursor);
}

uint64_t gak_native_asm_number(const GakAsmInstruction *instruction, uint32_t kind) {
    gak_asm_error = NULL;
    if (!instruction) {
        gak_asm_fail("invalid Instruction");
        return 0;
    }
    switch (kind) {
        case 1: return galeikan_asm_instruction_size(instruction->decoded);
        case 2: return instruction->offset;
        case 3: return instruction->offset + galeikan_asm_instruction_size(instruction->decoded);
        case 4: return galeikan_asm_instruction_ip(instruction->decoded);
        case 5: {
            uint64_t target = 0;
            if (galeikan_asm_instruction_target(instruction->decoded, &target)) return target;
            gak_asm_fail("instruction has no direct branch target");
            return 0;
        }
        case 6: {
            uint64_t target = 0;
            if (galeikan_asm_instruction_data_target(instruction->decoded, &target)) return target;
            gak_asm_fail("instruction has no IP-relative data target");
            return 0;
        }
        case 7: return (uint64_t)galeikan_asm_instruction_register_usage_complete(instruction->decoded);
        default:
            gak_asm_fail("unknown instruction numeric field");
            return 0;
    }
}
