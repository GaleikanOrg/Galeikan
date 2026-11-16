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
size_t galeikan_asm_instruction_text(const void *handle, uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_mnemonic(const void *handle, uint8_t *output, size_t capacity);
size_t galeikan_asm_instruction_flow(const void *handle, uint8_t *output, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
