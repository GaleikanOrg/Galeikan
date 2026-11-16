#include "native_asm_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
} GakAsmInstruction;

typedef struct GakAsmDisassembly {
    struct GakAsmDisassembly *next_owned;
    const GakSourceHead *source;
    uint64_t start_offset;
    void *decoded;
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
    instruction->next_owned = owned_instructions;
    owned_instructions = instruction;
    instruction_count++;
    return instruction;
}

GakAsmDisassembly *gak_native_asm_reachable(const GakSourceHead *source,
                                             int64_t offset, uint64_t base_ip,
                                             int64_t bitness, int64_t max_instructions) {
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
    if (galeikan_asm_reachable(bytes, (size_t)length, (size_t)offset, base_ip,
                               (uint32_t)bitness, (size_t)max_instructions,
                               &decoded, error, sizeof error)) {
        gak_asm_fail((const char *)error);
        return NULL;
    }
    size_t count = galeikan_asm_disassembly_count(decoded);
    if (count > 100000 - disassembly_instruction_count) {
        galeikan_asm_disassembly_free(decoded);
        gak_asm_fail("native Disassembly instruction count exceeds 100000");
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
    disassembly->next_owned = owned_disassemblies;
    owned_disassemblies = disassembly;
    disassembly_instruction_count += count;
    return disassembly;
}

uint64_t gak_native_asm_disassembly_count(const GakAsmDisassembly *disassembly) {
    gak_asm_error = NULL;
    if (!disassembly) {
        gak_asm_fail("invalid Disassembly");
        return 0;
    }
    return galeikan_asm_disassembly_count(disassembly->decoded);
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
    instruction->offset = (uint64_t)offset;
    instruction->decoded = decoded;
    instruction->next_owned = owned_instructions;
    owned_instructions = instruction;
    instruction_count++;
    return instruction;
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
