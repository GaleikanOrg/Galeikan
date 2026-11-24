#ifndef GALEIKAN_ASM_BRIDGE_H
#define GALEIKAN_ASM_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t galeikan_asm_decode(const uint8_t *bytes, size_t length, size_t offset,
                            uint64_t ip, uint32_t bitness, void **out,
                            uint8_t *error, size_t error_capacity);
int32_t galeikan_asm_reachable(const uint8_t *bytes, size_t length,
                               size_t start_offset, uint64_t base_ip,
                               uint32_t bitness, size_t max_instructions,
                               void **out, uint8_t *error, size_t error_capacity);
int32_t galeikan_asm_function_reachable(const uint8_t *bytes, size_t length,
                                        size_t start_offset, uint64_t base_ip,
                                        uint32_t bitness, size_t max_instructions,
                                        void **out, uint8_t *error, size_t error_capacity);
int32_t galeikan_asm_linear(const uint8_t *bytes, size_t length,
                            uint64_t base_ip, uint32_t bitness, size_t count,
                            void **out, uint8_t *error, size_t error_capacity);
void galeikan_asm_disassembly_free(void *handle);
size_t galeikan_asm_disassembly_count(const void *handle);
int32_t galeikan_asm_disassembly_bounds(const void *handle, size_t *start, size_t *end);
size_t galeikan_asm_disassembly_overlap_count(const void *handle);
int32_t galeikan_asm_disassembly_overlap_at(const void *handle, size_t index,
                                            int32_t *output);
typedef struct {
    uint64_t start;
    uint64_t end;
    size_t first_index;
    size_t instruction_count;
    size_t successor_count;
    int32_t unresolved;
} GaleikanAsmBlock;
size_t galeikan_asm_disassembly_block_count(const void *handle);
int32_t galeikan_asm_disassembly_block(const void *handle, size_t index,
                                       GaleikanAsmBlock *output);
int32_t galeikan_asm_disassembly_block_successor(const void *handle,
                                                 size_t block_index,
                                                 size_t successor_index,
                                                 uint64_t *output);
size_t galeikan_asm_disassembly_block_path(const void *handle, size_t from,
                                           size_t to, uint64_t *output,
                                           size_t capacity);
size_t galeikan_asm_disassembly_block_dominators(const void *handle, size_t entry,
                                                 size_t target, uint64_t *output,
                                                 size_t capacity);
size_t galeikan_asm_disassembly_block_natural_loop(const void *handle, size_t entry,
                                                   size_t header, size_t latch,
                                                   uint64_t *output, size_t capacity);
/* kind: 1=call targets, 2=data refs, 3=xrefs, 4=data xrefs. */
size_t galeikan_asm_disassembly_references(const void *handle, uint32_t kind,
                                            uint64_t target, uint64_t *output,
                                            size_t capacity);
/* Returns a separately owned instruction. Free it with instruction_free. */
int32_t galeikan_asm_disassembly_at(const void *handle, size_t index,
                                    void **out, size_t *offset);
void galeikan_asm_instruction_free(void *handle);
size_t galeikan_asm_instruction_size(const void *handle);
uint64_t galeikan_asm_instruction_ip(const void *handle);
int32_t galeikan_asm_sha256(const uint8_t *bytes, size_t length, uint8_t *output);
/* Optional addresses return 1 and write output when present, otherwise 0. */
int32_t galeikan_asm_instruction_target(const void *handle, uint64_t *output);
int32_t galeikan_asm_instruction_data_target(const void *handle, uint64_t *output);
int32_t galeikan_asm_instruction_register_usage_complete(const void *handle);
size_t galeikan_asm_instruction_text(const void *handle, uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_mnemonic(const void *handle, uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_flow(const void *handle, uint8_t *output, size_t capacity);
/* Text getters report the required UTF-8 byte length even when output is null. */
size_t galeikan_asm_instruction_register_reads_count(const void *handle);
size_t galeikan_asm_instruction_register_read(const void *handle, size_t index,
                                              uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_register_writes_count(const void *handle);
size_t galeikan_asm_instruction_register_write(const void *handle, size_t index,
                                               uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_flags_read_count(const void *handle);
size_t galeikan_asm_instruction_flag_read(const void *handle, size_t index,
                                          uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_flags_modified_count(const void *handle);
size_t galeikan_asm_instruction_flag_modified(const void *handle, size_t index,
                                              uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_successors_count(const void *handle);
int32_t galeikan_asm_instruction_successor(const void *handle, size_t index,
                                           uint64_t *output);

#ifdef __cplusplus
}
#endif

#endif
