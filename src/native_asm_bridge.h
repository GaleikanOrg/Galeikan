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
void galeikan_asm_instruction_free(void *handle);
size_t galeikan_asm_instruction_size(const void *handle);
uint64_t galeikan_asm_instruction_ip(const void *handle);
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
