#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Native Source: boxed backing, parent, start, end, and provenance fields. */
typedef struct {
    const uint8_t *backing;
    const void *parent;
    uint64_t start;
    uint64_t end;
} GakSourceHead;

typedef struct {
    const void *source;
    uint64_t kind; /* 1 = PE, 2 = ELF */
    uint64_t bits;
    uint64_t big_endian;
    uint64_t machine;
    uint64_t sections;
    uint64_t dll_characteristics;
    uint64_t dll_available;
    uint64_t section_wx;
    uint64_t file_type;
    uint64_t stack_flags;
    uint64_t stack_available;
    uint64_t program_headers_present;
    uint64_t relro_segment;
    uint64_t load_count;
    uint64_t load_rwx;
    uint64_t bind_now; /* 0 = unknown, 1 = absent, 2 = present */
    uint64_t machine_at;
    uint64_t entry_at;
    uint64_t entry_width;
    uint64_t entry;
    uint64_t sections_at;
    uint64_t sections_width;
    uint64_t dll_at;
    uint64_t image_base_at;
    uint64_t image_base_width;
    uint64_t stack_flags_at;
    uint64_t section_table;
    uint64_t section_stride;
    uint64_t name_table_offset;
    uint64_t name_table_size;
    uint64_t name_table_available;
    uint64_t headers_size;
    uint64_t headers_available;
    uint64_t declared_file_end;
    uint64_t program_table;
    uint64_t program_stride;
    uint64_t program_count;
} GakFormat;

typedef struct {
    const GakSourceHead *source;
    uint64_t start;
    uint64_t end;
    uint64_t address_kind; /* 0 = ordinary view, 1 = PE RVA, 2 = ELF VA */
    uint64_t address;
} GakFormatRange;

typedef struct {
    const void *source;
    uint64_t offset;
    uint64_t width;
    uint64_t value;
    const void *decoder;
} GakNumericField;

typedef struct {
    const GakSourceHead *source;
    const GakFormat *format;
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t virtual_address;
    uint64_t virtual_size;
    uint64_t flags;
    uint64_t writable;
    uint64_t executable;
    uint64_t file_backed;
    uint64_t index;
} GakSection;

typedef struct {
    uint64_t length;
    char text[128];
} GakText;

static const GakText text_pe = {2, "pe"};
static const GakText text_elf = {3, "elf"};
static const GakText text_little = {6, "little"};
static const GakText text_big = {3, "big"};
static const GakText text_unknown = {7, "unknown"};
static const GakText text_x86 = {3, "x86"};
static const GakText text_x86_64 = {6, "x86_64"};
static const GakText text_arm = {3, "arm"};
static const GakText text_aarch64 = {7, "aarch64"};
static const GakText text_riscv = {5, "riscv"};
static const GakText text_present = {7, "present"};
static const GakText text_absent = {6, "absent"};
static const GakText text_not_applicable = {14, "not_applicable"};
static const GakText text_u16le = {5, "u16le"};
static const GakText text_u16be = {5, "u16be"};
static const GakText text_u32le = {5, "u32le"};
static const GakText text_u32be = {5, "u32be"};
static const GakText text_u64le = {5, "u64le"};
static const GakText text_u64be = {5, "u64be"};
static const GakText text_name = {4, "name"};
static const GakText text_ordinal = {7, "ordinal"};
static const GakText text_rva = {3, "rva"};
static const GakText text_va = {2, "va"};
static const GakText text_section_offset = {14, "section_offset"};
static const GakText text_forwarder = {9, "forwarder"};
static GakText error_text;
uint8_t *gak_formats_error;
static size_t format_memory;

static void gak_format_fail(const char *message) {
    size_t length = strlen(message);
    if (length > sizeof(error_text.text)) length = sizeof(error_text.text);
    error_text.length = (uint64_t)length;
    memcpy(error_text.text, message, length);
    gak_formats_error = (uint8_t *)&error_text;
}

static int gak_span(uint64_t length, uint64_t offset, uint64_t width) {
    return offset <= length && width <= length - offset;
}

static uint64_t gak_number(const uint8_t *bytes, uint64_t offset,
                           unsigned width, int big) {
    uint64_t value = 0;
    for (unsigned index = 0; index < width; index++) {
        unsigned shift = big ? 8u * (width - index - 1u) : 8u * index;
        value |= (uint64_t)bytes[offset + index] << shift;
    }
    return value;
}

static int gak_pe(const uint8_t *bytes, uint64_t length, GakFormat *report) {
    if (!gak_span(length, 0, 64)) return 0;
    uint64_t offset = gak_number(bytes, 0x3c, 4, 0);
    if (offset < 64) { gak_format_fail("invalid PE offset"); return 0; }
    if (!gak_span(length, offset, 24)) return 0;
    if (memcmp(bytes + offset, "PE\0\0", 4) != 0) {
        gak_format_fail("missing PE signature");
        return 0;
    }
    uint64_t coff = offset + 4;
    uint64_t optional = coff + 20;
    uint64_t optional_size = gak_number(bytes, coff + 16, 2, 0);
    if (!gak_span(length, optional, optional_size)) return 0;
    if (optional_size < 20) { gak_format_fail("PE optional header too short"); return 0; }
    uint64_t magic = gak_number(bytes, optional, 2, 0);
    if (magic != 0x10b && magic != 0x20b) {
        gak_format_fail("invalid PE magic");
        return 0;
    }
    uint64_t sections = gak_number(bytes, coff + 2, 2, 0);
    if (!gak_span(length, optional + optional_size, sections * 40)) return 0;
    report->kind = 1;
    report->bits = magic == 0x10b ? 32 : 64;
    report->big_endian = 0;
    report->machine = gak_number(bytes, coff, 2, 0);
    report->machine_at = coff;
    report->sections = sections;
    report->section_table = optional + optional_size;
    report->section_stride = 40;
    report->sections_at = coff + 2;
    report->sections_width = 2;
    report->entry_at = optional + 16;
    report->entry_width = 4;
    report->entry = gak_number(bytes, report->entry_at, 4, 0);
    report->declared_file_end = report->section_table + sections * 40u;
    if (optional_size >= 64) {
        report->headers_available = 1;
        report->headers_size = gak_number(bytes, optional + 60, 4, 0);
        if (report->headers_size > report->declared_file_end)
            report->declared_file_end = report->headers_size;
    }
    if (optional_size >= 72) {
        report->dll_available = 1;
        report->dll_at = optional + 70;
        report->dll_characteristics = gak_number(bytes, optional + 70, 2, 0);
    }
    uint64_t image_base_offset = magic == 0x10b ? 28 : 24;
    uint64_t image_base_width = magic == 0x10b ? 4 : 8;
    if (optional_size >= image_base_offset + image_base_width) {
        report->image_base_at = optional + image_base_offset;
        report->image_base_width = image_base_width;
    }
    for (uint64_t index = 0; index < sections; index++) {
        uint64_t at = optional + optional_size + index * 40;
        uint64_t raw_size = gak_number(bytes, at + 16, 4, 0);
        uint64_t raw_offset = gak_number(bytes, at + 20, 4, 0);
        if (raw_size > 0 && raw_offset + raw_size > report->declared_file_end)
            report->declared_file_end = raw_offset + raw_size;
        uint64_t flags = gak_number(bytes, at + 36, 4, 0);
        if ((flags & 0xa0000000u) == 0xa0000000u) report->section_wx = 1;
    }
    return 1;
}

static int gak_elf(const uint8_t *bytes, uint64_t length, GakFormat *report) {
    if (!gak_span(length, 0, 16)) return 0;
    unsigned width;
    uint64_t header_size, shoff_at, shentsize_at, shnum_at, phoff_at, phentsize_at, phnum_at;
    if (bytes[4] == 1) {
        width = 4; header_size = 52; shoff_at = 32; shentsize_at = 46; shnum_at = 48;
        phoff_at = 28; phentsize_at = 42; phnum_at = 44;
    } else if (bytes[4] == 2) {
        width = 8; header_size = 64; shoff_at = 40; shentsize_at = 58; shnum_at = 60;
        phoff_at = 32; phentsize_at = 54; phnum_at = 56;
    } else { gak_format_fail("invalid ELF class"); return 0; }
    if (bytes[5] != 1 && bytes[5] != 2) {
        gak_format_fail("invalid ELF byte order"); return 0;
    }
    int big = bytes[5] == 2;
    if (bytes[6] != 1 || !gak_span(length, 0, header_size) ||
        gak_number(bytes, 20, 4, big) != 1 ||
        gak_number(bytes, width == 4 ? 40 : 52, 2, big) != header_size) {
        gak_format_fail("invalid ELF header"); return 0;
    }
    uint64_t shoff = gak_number(bytes, shoff_at, width, big);
    uint64_t shentsize = gak_number(bytes, shentsize_at, 2, big);
    uint64_t shnum = gak_number(bytes, shnum_at, 2, big);
    uint64_t shstrndx = gak_number(bytes, width == 4 ? 50 : 62, 2, big);
    report->sections_at = shnum_at;
    report->sections_width = 2;
    report->declared_file_end = header_size;
    if (shoff == 0) {
        if (shnum != 0 || shstrndx != 0) {
            gak_format_fail("ELF sections without a section table"); return 0;
        }
    } else {
        if (shentsize != (width == 4 ? 40u : 64u) ||
            !gak_span(length, shoff, shentsize)) {
            gak_format_fail("invalid ELF section table"); return 0;
        }
        if (shnum == 0) {
            report->sections_at = shoff + (width == 4 ? 20 : 32);
            report->sections_width = width;
            shnum = gak_number(bytes, report->sections_at, width, big);
        }
        if (shnum > 100000 || shnum > UINT64_MAX / shentsize ||
            !gak_span(length, shoff, shnum * shentsize)) {
            gak_format_fail("invalid ELF section count"); return 0;
        }
        if (shnum > 0) {
            uint64_t name_index = shstrndx == 0xffff
                ? gak_number(bytes, shoff + (width == 4 ? 24 : 40), 4, big)
                : shstrndx;
            if (name_index >= shnum) {
                gak_format_fail("ELF section name table index out of range"); return 0;
            }
            if (name_index != 0) {
                uint64_t name_at = shoff + name_index * shentsize;
                uint64_t file_offset = gak_number(bytes, name_at + (width == 4 ? 16 : 24), width, big);
                uint64_t file_size = gak_number(bytes, name_at + (width == 4 ? 20 : 32), width, big);
                if (gak_span(length, file_offset, file_size)) {
                    report->name_table_available = 1;
                    report->name_table_offset = file_offset;
                    report->name_table_size = file_size;
                }
            }
        } else if (shstrndx != 0) {
            gak_format_fail("ELF section names without a section table"); return 0;
        }
        for (uint64_t index = 0; index < shnum; index++) {
            uint64_t at = shoff + index * shentsize;
            uint64_t kind = gak_number(bytes, at + 4, 4, big);
            uint64_t file_offset = gak_number(bytes, at + (width == 4 ? 16 : 24), width, big);
            uint64_t file_size = gak_number(bytes, at + (width == 4 ? 20 : 32), width, big);
            if (index != 0 && kind != 8 && file_size > 0 &&
                file_offset > UINT64_MAX - file_size) {
                gak_format_fail("ELF section range overflow"); return 0;
            }
            if (index != 0 && kind != 8 && file_size > 0 &&
                file_offset + file_size > report->declared_file_end)
                report->declared_file_end = file_offset + file_size;
        }
        if (shoff + shnum * shentsize > report->declared_file_end)
            report->declared_file_end = shoff + shnum * shentsize;
    }
    uint64_t phoff = gak_number(bytes, phoff_at, width, big);
    uint64_t phentsize = gak_number(bytes, phentsize_at, 2, big);
    uint64_t phnum = gak_number(bytes, phnum_at, 2, big);
    if (phnum == 0xffff) {
        if (shoff == 0 || shentsize == 0) {
            gak_format_fail("extended ELF program count needs section header zero"); return 0;
        }
        phnum = gak_number(bytes, shoff + (width == 4 ? 28 : 44), 4, big);
    }
    if (phnum > 10000) { gak_format_fail("ELF program count exceeds limit"); return 0; }
    if (phnum > 0 && (phoff == 0 || phentsize != (width == 4 ? 32u : 56u) ||
                      phnum > UINT64_MAX / phentsize ||
                      !gak_span(length, phoff, phnum * phentsize))) {
        gak_format_fail("invalid ELF program header table"); return 0;
    }
    report->program_table = phoff;
    report->program_stride = phentsize;
    report->program_count = phnum;
    if (phnum > 0 && phoff + phnum * phentsize > report->declared_file_end)
        report->declared_file_end = phoff + phnum * phentsize;
    int dynamic_seen = 0;
    uint64_t dynamic_offset = 0, dynamic_size = 0;
    for (uint64_t index = 0; index < phnum; index++) {
        uint64_t at = phoff + index * phentsize;
        uint64_t kind = gak_number(bytes, at, 4, big);
        uint64_t file_offset = gak_number(bytes, at + (width == 4 ? 4 : 8), width, big);
        uint64_t file_size = gak_number(bytes, at + (width == 4 ? 16 : 32), width, big);
        if (kind != 0 && file_size > 0 && file_offset > UINT64_MAX - file_size) {
            gak_format_fail("ELF segment file range overflow"); return 0;
        }
        if (kind != 0 && file_size > 0 &&
            file_offset + file_size > report->declared_file_end)
            report->declared_file_end = file_offset + file_size;
        if (kind == 0x6474e551u) {
            report->stack_available = 1;
            report->stack_flags_at = at + (width == 4 ? 24 : 4);
            report->stack_flags = gak_number(bytes, at + (width == 4 ? 24 : 4), 4, big);
        }
        if (kind == 0x6474e552u) {
            uint64_t size = gak_number(bytes, at + (width == 4 ? 20 : 40), width, big);
            if (size > 0) report->relro_segment = 1;
        }
        if (kind == 2 && dynamic_seen++) {
            gak_format_fail("multiple ELF PT_DYNAMIC segments"); return 0;
        }
        if (kind == 2) { dynamic_offset = file_offset; dynamic_size = file_size; }
        if (kind != 1) continue;
        uint64_t memory_size = gak_number(bytes, at + (width == 4 ? 20 : 40), width, big);
        if (file_size > memory_size) {
            gak_format_fail("ELF load segment file size exceeds memory size"); return 0;
        }
        uint64_t virtual_address = gak_number(bytes, at + (width == 4 ? 8 : 16), width, big);
        if (virtual_address > UINT64_MAX - memory_size) {
            gak_format_fail("ELF segment VA overflow"); return 0;
        }
        if (width == 4 && virtual_address + memory_size > (uint64_t)UINT32_MAX + 1u) {
            gak_format_fail("ELF load segment outside ELF32 address space"); return 0;
        }
        report->load_count++;
        uint64_t flags = gak_number(bytes, at + (width == 4 ? 24 : 4), 4, big);
        if ((flags & 7u) == 7u) report->load_rwx = 1;
    }
    if (dynamic_seen && dynamic_size > 0 && dynamic_size <= 1024u * 1024u &&
        dynamic_size % (width * 2u) == 0 && gak_span(length, dynamic_offset, dynamic_size)) {
        int marker = 0, flags_seen = 0, flags1_seen = 0, duplicate = 0, terminated = 0;
        uint64_t flags = 0, flags1 = 0;
        for (uint64_t index = 0; index < dynamic_size / (width * 2u); index++) {
            uint64_t at = dynamic_offset + index * (width * 2u);
            uint64_t tag = gak_number(bytes, at, width, big);
            if (tag == 0) { terminated = 1; break; }
            if (tag != 24 && tag != 30 && tag != 0x6ffffffbu) continue;
            uint64_t value = gak_number(bytes, at + width, width, big);
            if (tag == 24) { if (marker) duplicate = 1; marker = 1; }
            if (tag == 30) { if (flags_seen) duplicate = 1; flags_seen = 1; flags = value; }
            if (tag == 0x6ffffffbu) { if (flags1_seen) duplicate = 1; flags1_seen = 1; flags1 = value; }
        }
        if (terminated && !duplicate) {
            report->bind_now = marker || (flags_seen && (flags & 8u)) ||
                               (flags1_seen && (flags1 & 1u)) ? 2 : 1;
        }
    }
    report->kind = 2;
    report->bits = width * 8u;
    report->big_endian = (uint64_t)big;
    report->machine = gak_number(bytes, 18, 2, big);
    report->machine_at = 18;
    report->entry_at = 24;
    report->entry_width = width;
    report->entry = gak_number(bytes, 24, width, big);
    report->sections = shnum;
    report->section_table = shoff;
    report->section_stride = shentsize;
    report->file_type = gak_number(bytes, 16, 2, big);
    report->program_headers_present = phnum != 0;
    return 1;
}

void *gak_native_formats_probe(const void *source_pointer) {
    gak_formats_error = NULL;
    if (!source_pointer) { gak_format_fail("invalid Source"); return NULL; }
    const GakSourceHead *source = source_pointer;
    if (!source->backing || source->start > source->end) {
        gak_format_fail("invalid Source"); return NULL;
    }
    uint64_t backing_size;
    memcpy(&backing_size, source->backing, sizeof(backing_size));
    if (source->end > backing_size) { gak_format_fail("invalid Source"); return NULL; }
    if (format_memory > 64u * 1024u * 1024u - sizeof(GakFormat)) {
        gak_format_fail("format memory limit"); return NULL;
    }
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    GakFormat report = {0};
    report.source = source_pointer;
    int valid;
    if (length >= 2 && memcmp(bytes, "MZ", 2) == 0) {
        valid = gak_pe(bytes, length, &report);
    } else if (length >= 4 && memcmp(bytes, "\x7f" "ELF", 4) == 0) {
        valid = gak_elf(bytes, length, &report);
    } else {
        gak_format_fail("unknown binary format"); return NULL;
    }
    if (!valid) {
        if (!gak_formats_error) gak_format_fail("truncated binary header");
        return NULL;
    }
    GakFormat *result = malloc(sizeof(*result));
    if (!result) { gak_format_fail("native allocation failed"); return NULL; }
    *result = report;
    format_memory += sizeof(*result);
    return result;
}

uint64_t gak_native_formats_bits(const void *value) { return ((const GakFormat *)value)->bits; }
uint64_t gak_native_formats_count(const void *value) { return ((const GakFormat *)value)->sections; }
const void *gak_native_formats_kind(const void *value) {
    return ((const GakFormat *)value)->kind == 1 ? &text_pe : &text_elf;
}
const void *gak_native_formats_endian(const void *value) {
    return ((const GakFormat *)value)->big_endian ? &text_big : &text_little;
}
const void *gak_native_formats_arch(const void *value) {
    const GakFormat *format = value;
    uint64_t machine = format->machine;
    if ((format->kind == 1 && machine == 0x014c) || (format->kind == 2 && machine == 3)) return &text_x86;
    if ((format->kind == 1 && machine == 0x8664) || (format->kind == 2 && machine == 62)) return &text_x86_64;
    if ((format->kind == 1 && (machine == 0x01c0 || machine == 0x01c2 || machine == 0x01c4)) ||
        (format->kind == 2 && machine == 40)) return &text_arm;
    if ((format->kind == 1 && (machine == 0xaa64 || machine == 0xa641 || machine == 0xa64e)) ||
        (format->kind == 2 && machine == 183)) return &text_aarch64;
    if ((format->kind == 1 && (machine == 0x5032 || machine == 0x5064 || machine == 0x5128)) ||
        (format->kind == 2 && machine == 243)) return &text_riscv;
    return &text_unknown;
}

static int gak_format_name(const void *boxed, const char *literal) {
    if (!boxed) return 0;
    uint64_t length;
    memcpy(&length, boxed, sizeof(length));
    size_t expected = strlen(literal);
    return length == expected && memcmp((const uint8_t *)boxed + 8, literal, expected) == 0;
}

void *gak_native_formats_field(const void *value, const void *name) {
    const GakFormat *format = value;
    gak_formats_error = NULL;
    if (!format || !name) { gak_format_fail("invalid format field"); return NULL; }
    uint64_t offset = 0, width = 0, number = 0;
    if (gak_format_name(name, "machine")) {
        offset = format->machine_at; width = 2; number = format->machine;
    } else if (gak_format_name(name, "entry")) {
        offset = format->entry_at; width = format->entry_width; number = format->entry;
    } else if (gak_format_name(name, "sections")) {
        offset = format->sections_at; width = format->sections_width; number = format->sections;
    } else if (gak_format_name(name, "dll_characteristics") && format->dll_available) {
        offset = format->dll_at; width = 2; number = format->dll_characteristics;
    } else if (gak_format_name(name, "image_base") && format->image_base_width) {
        offset = format->image_base_at; width = format->image_base_width;
        const GakSourceHead *source = format->source;
        const uint8_t *bytes = source->backing + 8 + source->start;
        number = gak_number(bytes, offset, (unsigned)width, 0);
    } else if (gak_format_name(name, "file_type") && format->kind == 2) {
        offset = 16; width = 2; number = format->file_type;
    } else if (gak_format_name(name, "gnu_stack_flags") && format->stack_available) {
        offset = format->stack_flags_at; width = 4; number = format->stack_flags;
    } else {
        gak_format_fail("unknown format field"); return NULL;
    }
    const void *decoder;
    if (width == 2) decoder = format->big_endian ? (const void *)&text_u16be : (const void *)&text_u16le;
    else if (width == 4) decoder = format->big_endian ? (const void *)&text_u32be : (const void *)&text_u32le;
    else decoder = format->big_endian ? (const void *)&text_u64be : (const void *)&text_u64le;
    if (format_memory > 64u * 1024u * 1024u - sizeof(GakNumericField)) {
        gak_format_fail("format memory limit"); return NULL;
    }
    GakNumericField *result = malloc(sizeof(*result));
    if (!result) { gak_format_fail("native allocation failed"); return NULL; }
    *result = (GakNumericField){format->source, offset, width, number, decoder};
    format_memory += sizeof(*result);
    return result;
}

void *gak_native_formats_section(const void *value, int64_t index) {
    const GakFormat *format = value;
    gak_formats_error = NULL;
    if (!format || index < 0 || (uint64_t)index >= format->sections) {
        gak_format_fail("section index out of range"); return NULL;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t at = format->section_table + (uint64_t)index * format->section_stride;
    GakSection section = {0};
    section.source = source;
    section.format = format;
    section.index = (uint64_t)index;
    if (format->kind == 1) {
        section.virtual_size = gak_number(bytes, at + 8, 4, 0);
        section.virtual_address = gak_number(bytes, at + 12, 4, 0);
        section.file_size = gak_number(bytes, at + 16, 4, 0);
        section.file_offset = gak_number(bytes, at + 20, 4, 0);
        section.flags = gak_number(bytes, at + 36, 4, 0);
        section.writable = (section.flags & 0x80000000u) != 0;
        section.executable = (section.flags & 0x20000000u) != 0;
        section.file_backed = section.file_size != 0;
    } else {
        unsigned width = format->bits == 32 ? 4 : 8;
        int big = format->big_endian != 0;
        uint64_t kind = gak_number(bytes, at + 4, 4, big);
        section.flags = gak_number(bytes, at + 8, width, big);
        section.virtual_address = gak_number(bytes, at + (width == 4 ? 12 : 16), width, big);
        section.file_offset = gak_number(bytes, at + (width == 4 ? 16 : 24), width, big);
        section.virtual_size = gak_number(bytes, at + (width == 4 ? 20 : 32), width, big);
        section.file_size = index == 0 || kind == 8 ? 0 : section.virtual_size;
        section.writable = (section.flags & 1u) != 0;
        section.executable = (section.flags & 4u) != 0;
        section.file_backed = index != 0 && kind != 8 && section.file_size != 0;
    }
    if (format_memory > 64u * 1024u * 1024u - sizeof(GakSection)) {
        gak_format_fail("format memory limit"); return NULL;
    }
    GakSection *result = malloc(sizeof(*result));
    if (!result) { gak_format_fail("native allocation failed"); return NULL; }
    *result = section;
    format_memory += sizeof(*result);
    return result;
}

static void *gak_format_box(const char *text, size_t length) {
    if (length > 64u * 1024u * 1024u - 8u ||
        format_memory > 64u * 1024u * 1024u - 8u - length) {
        gak_format_fail("format memory limit"); return NULL;
    }
    uint8_t *box = malloc(length + 8);
    if (!box) { gak_format_fail("native allocation failed"); return NULL; }
    uint64_t wide = (uint64_t)length;
    memcpy(box, &wide, 8);
    if (length) memcpy(box + 8, text, length);
    format_memory += length + 8;
    return box;
}

void *gak_native_formats_section_name(const void *value) {
    const GakSection *section = value;
    gak_formats_error = NULL;
    if (!section) { gak_format_fail("invalid Section"); return NULL; }
    const GakFormat *format = section->format;
    const GakSourceHead *source = section->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t at = format->section_table + section->index * format->section_stride;
    const uint8_t *raw;
    size_t length;
    if (format->kind == 1) {
        raw = bytes + at;
        length = 0;
        while (length < 8 && raw[length]) length++;
    } else {
        if (!format->name_table_available) {
            gak_format_fail("section name unavailable in captured Source"); return NULL;
        }
        uint64_t name_index = gak_number(bytes, at, 4, format->big_endian != 0);
        if (name_index >= format->name_table_size) {
            gak_format_fail("section name unavailable in captured Source"); return NULL;
        }
        raw = bytes + format->name_table_offset + name_index;
        uint64_t remaining = format->name_table_size - name_index;
        length = 0;
        while ((uint64_t)length < remaining && raw[length]) length++;
        if ((uint64_t)length == remaining) {
            gak_format_fail("section name unavailable in captured Source"); return NULL;
        }
    }
    if (length > 1024u * 1024u) {
        gak_format_fail("section name exceeds native limit"); return NULL;
    }
    size_t escaped = 0;
    for (size_t index = 0; index < length; index++)
        escaped += raw[index] >= 0x20 && raw[index] <= 0x7e ? 1u : 4u;
    if (escaped > 64u * 1024u * 1024u - 8u ||
        format_memory > 64u * 1024u * 1024u - 8u - escaped) {
        gak_format_fail("format memory limit"); return NULL;
    }
    uint8_t *box = malloc(escaped + 8);
    if (!box) { gak_format_fail("native allocation failed"); return NULL; }
    uint64_t wide = (uint64_t)escaped;
    memcpy(box, &wide, 8);
    static const char digits[] = "0123456789abcdef";
    size_t cursor = 8;
    for (size_t index = 0; index < length; index++) {
        uint8_t byte = raw[index];
        if (byte >= 0x20 && byte <= 0x7e) box[cursor++] = byte;
        else {
            box[cursor++] = '\\'; box[cursor++] = 'x';
            box[cursor++] = digits[byte >> 4]; box[cursor++] = digits[byte & 15];
        }
    }
    format_memory += escaped + 8;
    return box;
}

static void *gak_format_hex(uint64_t value) {
    char text[32];
    int length = snprintf(text, sizeof(text), "0x%llx", (unsigned long long)value);
    if (length < 0 || (size_t)length >= sizeof(text)) {
        gak_format_fail("invalid section address"); return NULL;
    }
    return gak_format_box(text, (size_t)length);
}

void *gak_native_formats_section_address(const void *value) {
    return gak_format_hex(((const GakSection *)value)->virtual_address);
}
void *gak_native_formats_section_flags(const void *value) {
    return gak_format_hex(((const GakSection *)value)->flags);
}
uint64_t gak_native_formats_section_offset(const void *value) { return ((const GakSection *)value)->file_offset; }
uint64_t gak_native_formats_section_size(const void *value) { return ((const GakSection *)value)->file_size; }
uint64_t gak_native_formats_section_virtual_size(const void *value) { return ((const GakSection *)value)->virtual_size; }
uint64_t gak_native_formats_section_writable(const void *value) { return ((const GakSection *)value)->writable; }
uint64_t gak_native_formats_section_executable(const void *value) { return ((const GakSection *)value)->executable; }

void *gak_native_formats_section_data(const void *value) {
    const GakSection *section = value;
    gak_formats_error = NULL;
    if (!section || !section->file_backed) {
        gak_format_fail("section has no file-backed bytes"); return NULL;
    }
    uint64_t length = section->source->end - section->source->start;
    if (!gak_span(length, section->file_offset, section->file_size)) {
        gak_format_fail("section data outside captured Source"); return NULL;
    }
    return (void *)section;
}

static GakFormatRange *gak_format_range(const GakFormat *format,
                                        uint64_t start, uint64_t end,
                                        uint64_t address_kind, uint64_t address) {
    if (format_memory > 64u * 1024u * 1024u - sizeof(GakFormatRange)) {
        gak_format_fail("format memory limit"); return NULL;
    }
    GakFormatRange *range = malloc(sizeof(*range));
    if (!range) { gak_format_fail("native allocation failed"); return NULL; }
    *range = (GakFormatRange){format->source, start, end, address_kind, address};
    format_memory += sizeof(*range);
    return range;
}

static GakFormatRange *gak_pe_rva(const GakFormat *format, uint64_t rva,
                                  uint64_t count) {
    if (format->kind != 1) {
        gak_format_fail("formats.rva requires a PE image"); return NULL;
    }
    if (!count) { gak_format_fail("RVA view length must be positive"); return NULL; }
    if (rva > UINT64_MAX - count) {
        gak_format_fail("RVA range overflow"); return NULL;
    }
    uint64_t end = rva + count;
    if (end > (uint64_t)UINT32_MAX + 1u) {
        gak_format_fail("RVA range outside PE address space"); return NULL;
    }
    int mapped = 0;
    uint64_t file_start = 0, file_end = 0;
    if (format->headers_available && rva < format->headers_size) {
        if (end > format->headers_size) {
            gak_format_fail("RVA range crosses PE header boundary"); return NULL;
        }
        file_start = rva; file_end = end; mapped = 1;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    for (uint64_t index = 0; index < format->sections; index++) {
        uint64_t at = format->section_table + index * 40u;
        uint64_t virtual_size = gak_number(bytes, at + 8, 4, 0);
        uint64_t start = gak_number(bytes, at + 12, 4, 0);
        uint64_t raw_size = gak_number(bytes, at + 16, 4, 0);
        uint64_t raw_offset = gak_number(bytes, at + 20, 4, 0);
        uint64_t section_size = virtual_size > raw_size ? virtual_size : raw_size;
        uint64_t section_end = start + section_size;
        if (rva < start || rva >= section_end) continue;
        if (end > section_end) {
            gak_format_fail("RVA range crosses PE section boundary"); return NULL;
        }
        uint64_t within = rva - start;
        if (within + count > raw_size) {
            gak_format_fail("RVA range has no file-backed bytes"); return NULL;
        }
        if (mapped) { gak_format_fail("RVA maps to multiple PE regions"); return NULL; }
        file_start = raw_offset + within;
        file_end = file_start + count;
        mapped = 1;
    }
    if (!mapped) { gak_format_fail("RVA is not mapped to PE file bytes"); return NULL; }
    if (file_end > source->end - source->start) {
        gak_format_fail("RVA data outside captured Source"); return NULL;
    }
    return gak_format_range(format, file_start, file_end, 1, rva);
}

static GakFormatRange *gak_elf_va(const GakFormat *format, uint64_t va,
                                  uint64_t count) {
    if (format->kind != 2) {
        gak_format_fail("formats.va requires an ELF image"); return NULL;
    }
    if (!count) { gak_format_fail("VA view length must be positive"); return NULL; }
    if (va > UINT64_MAX - count) { gak_format_fail("VA range overflow"); return NULL; }
    uint64_t end = va + count;
    if (format->bits == 32 && end > (uint64_t)UINT32_MAX + 1u) {
        gak_format_fail("VA range outside ELF32 address space"); return NULL;
    }
    int mapped = 0;
    uint64_t file_start = 0, file_end = 0;
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    unsigned width = format->bits == 32 ? 4 : 8;
    int big = format->big_endian != 0;
    for (uint64_t index = 0; index < format->program_count; index++) {
        uint64_t at = format->program_table + index * format->program_stride;
        if (gak_number(bytes, at, 4, big) != 1) continue;
        uint64_t start = gak_number(bytes, at + (width == 4 ? 8 : 16), width, big);
        uint64_t memory_size = gak_number(bytes, at + (width == 4 ? 20 : 40), width, big);
        uint64_t segment_end = start + memory_size;
        if (va < start || va >= segment_end) continue;
        if (end > segment_end) {
            gak_format_fail("VA range crosses ELF load segment boundary"); return NULL;
        }
        uint64_t within = va - start;
        uint64_t raw_size = gak_number(bytes, at + (width == 4 ? 16 : 32), width, big);
        if (within > UINT64_MAX - count || within + count > raw_size) {
            gak_format_fail("VA range has no file-backed bytes"); return NULL;
        }
        uint64_t raw_offset = gak_number(bytes, at + (width == 4 ? 4 : 8), width, big);
        if (raw_offset > UINT64_MAX - within ||
            raw_offset + within > UINT64_MAX - count) {
            gak_format_fail("ELF file range overflow"); return NULL;
        }
        if (mapped) {
            gak_format_fail("VA maps to multiple ELF load segments"); return NULL;
        }
        file_start = raw_offset + within;
        file_end = file_start + count;
        mapped = 1;
    }
    if (!mapped) { gak_format_fail("VA is not mapped to ELF file bytes"); return NULL; }
    if (file_end > source->end - source->start) {
        gak_format_fail("VA data outside captured Source"); return NULL;
    }
    return gak_format_range(format, file_start, file_end, 2, va);
}

void *gak_native_formats_rva(const void *value, int64_t address, int64_t count) {
    gak_formats_error = NULL;
    if (address < 0) { gak_format_fail("RVA must not be negative"); return NULL; }
    if (count < 0) { gak_format_fail("RVA view length must not be negative"); return NULL; }
    return gak_pe_rva(value, (uint64_t)address, (uint64_t)count);
}

void *gak_native_formats_va(const void *value, int64_t address, int64_t count) {
    gak_formats_error = NULL;
    if (address < 0) { gak_format_fail("VA must not be negative"); return NULL; }
    if (count < 0) { gak_format_fail("VA view length must not be negative"); return NULL; }
    return gak_elf_va(value, (uint64_t)address, (uint64_t)count);
}

void *gak_native_formats_entry_view(const void *value, int64_t count) {
    const GakFormat *format = value;
    gak_formats_error = NULL;
    if (count < 0) { gak_format_fail("entry view length must not be negative"); return NULL; }
    return format->kind == 1
        ? gak_pe_rva(format, format->entry, (uint64_t)count)
        : gak_elf_va(format, format->entry, (uint64_t)count);
}

void *gak_native_formats_overlay(const void *value) {
    const GakFormat *format = value;
    gak_formats_error = NULL;
    const GakSourceHead *source = format->source;
    uint64_t length = source->end - source->start;
    if (format->declared_file_end > length) {
        gak_format_fail("declared binary extent outside captured Source"); return NULL;
    }
    return gak_format_range(format, format->declared_file_end, length, 0, 0);
}

typedef struct {
    uint64_t count;
    uint64_t offset;
    uint64_t size;
    uint64_t revision;
    uint64_t kind;
} GakCertificateSelection;

static int gak_pe_certificate_scan(const GakFormat *format, int64_t selected,
                                   GakCertificateSelection *result) {
    if (format->kind != 1) {
        gak_format_fail("PE certificates require a PE image"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t directory_offset = (format->bits == 32 ? 96 : 112) + 32;
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (gak_number(bytes, optional + count_offset, 4, 0) < 5) return 1;
    if (optional_size < directory_offset + 8) {
        gak_format_fail("PE certificate directory lies outside optional header"); return 0;
    }
    uint64_t start = gak_number(bytes, optional + directory_offset, 4, 0);
    uint64_t size = gak_number(bytes, optional + directory_offset + 4, 4, 0);
    if (!start && !size) return 1;
    if (!start || !size) {
        gak_format_fail("incomplete PE certificate directory"); return 0;
    }
    if (size > 16u * 1024u * 1024u) {
        gak_format_fail("PE certificate table exceeds 16777216 bytes"); return 0;
    }
    if (start % 8u) {
        gak_format_fail("PE certificate table is not 8-byte aligned"); return 0;
    }
    if (start < format->declared_file_end) {
        gak_format_fail("PE certificate table overlaps headers or sections"); return 0;
    }
    if (!gak_span(length, start, size)) {
        gak_format_fail("PE certificate table outside captured Source"); return 0;
    }
    uint64_t end = start + size;
    for (uint64_t current = start; current < end;) {
        if (result->count >= 4096) {
            gak_format_fail("PE certificate count exceeds 4096"); return 0;
        }
        if (end - current < 8) {
            gak_format_fail("truncated PE certificate entry"); return 0;
        }
        uint64_t entry_length = gak_number(bytes, current, 4, 0);
        if (entry_length < 8) {
            gak_format_fail("PE certificate entry is shorter than its header"); return 0;
        }
        uint64_t aligned = (entry_length + 7u) & ~7u;
        if (aligned > end - current) {
            gak_format_fail("PE certificate entries exceed directory size"); return 0;
        }
        if (selected >= 0 && (uint64_t)selected == result->count) {
            result->offset = current + 8;
            result->size = entry_length - 8;
            result->revision = gak_number(bytes, current + 4, 2, 0);
            result->kind = gak_number(bytes, current + 6, 2, 0);
        }
        result->count++;
        current += aligned;
    }
    return 1;
}

int64_t gak_native_formats_certificate_count(const void *value) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakCertificateSelection result = {0};
    if (!gak_pe_certificate_scan(value, -1, &result)) return -1;
    return (int64_t)result.count;
}

int64_t gak_native_formats_certificate_number(const void *value, int64_t index,
                                               int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    if (index < 0) { gak_format_fail("certificate index out of range"); return -1; }
    GakCertificateSelection result = {0};
    if (!gak_pe_certificate_scan(value, index, &result)) return -1;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("certificate index out of range"); return -1;
    }
    uint64_t number = part == 0 ? result.offset : part == 1 ? result.size
                    : part == 2 ? result.revision : result.kind;
    if (number > INT64_MAX) {
        gak_format_fail(part == 0 ? "certificate offset outside i64 range"
                        : "certificate size outside i64 range"); return -1;
    }
    return (int64_t)number;
}

void *gak_native_formats_certificate_data(const void *value, int64_t index) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("certificate index out of range"); return NULL; }
    GakCertificateSelection result = {0};
    if (!gak_pe_certificate_scan(value, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("certificate index out of range"); return NULL;
    }
    return gak_format_range(value, result.offset, result.offset + result.size, 0, 0);
}

/* Dependency lookups validate the complete table, including entries after the
 * requested index, so count and name have the same malformed-input behavior. */
static int gak_dependency_map(const GakFormat *format, int pe, uint64_t address,
                              uint64_t length, uint64_t *start) {
    GakFormatRange *range = pe ? gak_pe_rva(format, address, length)
                               : gak_elf_va(format, address, length);
    if (!range) return 0;
    *start = range->start;
    free(range);
    format_memory -= sizeof(*range);
    return 1;
}

typedef struct {
    uint64_t count;
    uint64_t address;
    uint64_t kind;
    uint64_t symbol;
    int64_t addend;
    int has_addend;
    int relr;
} GakRelocationSelection;

static int gak_relocation_emit(GakRelocationSelection *result, int64_t selected,
                               uint64_t address, uint64_t kind,
                               uint64_t symbol, int64_t addend,
                               int has_addend, int relr) {
    if (result->count >= 100000) {
        gak_format_fail("ELF relocation limit exceeded"); return 0;
    }
    if (selected >= 0 && (uint64_t)selected == result->count) {
        result->address = address;
        result->kind = kind;
        result->symbol = symbol;
        result->addend = addend;
        result->has_addend = has_addend;
        result->relr = relr;
    }
    result->count++;
    return 1;
}

static int gak_pe_relocation_scan(const GakFormat *format, int64_t selected,
                                  GakRelocationSelection *result) {
    if (format->kind != 1) {
        gak_format_fail("native ELF relocations are not yet supported"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t directory_offset = (format->bits == 32 ? 96 : 112) + 40;
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (gak_number(bytes, optional + count_offset, 4, 0) < 6) return 1;
    if (optional_size < directory_offset + 8) {
        gak_format_fail("PE base relocation directory lies outside optional header"); return 0;
    }
    uint64_t directory_rva = gak_number(bytes, optional + directory_offset, 4, 0);
    uint64_t directory_size = gak_number(bytes, optional + directory_offset + 4, 4, 0);
    if (!directory_rva && !directory_size) return 1;
    if (!directory_rva || !directory_size) {
        gak_format_fail("incomplete PE base relocation directory"); return 0;
    }
    if (directory_size > 16u * 1024u * 1024u) {
        gak_format_fail("PE base relocation directory exceeds 16 MiB"); return 0;
    }
    uint64_t end = directory_rva + directory_size;
    if (end > (uint64_t)UINT32_MAX + 1u) {
        gak_format_fail("PE base relocation directory outside RVA space"); return 0;
    }
    uint64_t cursor = directory_rva, blocks = 0, slots = 0;
    while (cursor < end) {
        if (blocks == 65536) {
            gak_format_fail("PE base relocation block limit exceeded"); return 0;
        }
        if (end - cursor < 8) {
            gak_format_fail("truncated PE base relocation block header"); return 0;
        }
        uint64_t header;
        if (!gak_dependency_map(format, 1, cursor, 8, &header)) return 0;
        uint64_t page_rva = gak_number(bytes, header, 4, 0);
        uint64_t block_size = gak_number(bytes, header + 4, 4, 0);
        if (block_size < 8 || block_size % 2 || block_size > end - cursor) {
            gak_format_fail("invalid PE base relocation block size"); return 0;
        }
        uint64_t count = (block_size - 8) / 2;
        slots += count;
        if (slots > 100000) {
            gak_format_fail("PE base relocation slot limit exceeded"); return 0;
        }
        if (count) {
            uint64_t body;
            if (!gak_dependency_map(format, 1, cursor + 8, count * 2, &body)) return 0;
            for (uint64_t index = 0; index < count; index++) {
                uint64_t entry = gak_number(bytes, body + index * 2, 2, 0);
                uint64_t kind = entry >> 12;
                uint64_t address = page_rva + (entry & 0xfffu);
                if (address > UINT32_MAX) {
                    gak_format_fail("PE base relocation RVA outside address space"); return 0;
                }
                if (kind) {
                    if (!gak_relocation_emit(result, selected, address, kind,
                                             0, 0, 0, 0)) return 0;
                }
                if (kind == 4) {
                    if (index + 1 >= count) {
                        gak_format_fail("PE HIGHADJ relocation lacks its pair"); return 0;
                    }
                    index++;
                }
            }
        }
        cursor += block_size;
        blocks++;
    }
    return 1;
}

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint64_t entry_size;
    int encoding; /* 0 = REL, 1 = RELA, 2 = RELR */
} GakRelocationTable;

static int gak_relocation_table_compare(const void *left, const void *right) {
    const GakRelocationTable *a = left, *b = right;
    if (a->offset != b->offset) return a->offset < b->offset ? -1 : 1;
    if (a->size != b->size) return a->size < b->size ? -1 : 1;
    if (a->entry_size != b->entry_size)
        return a->entry_size < b->entry_size ? -1 : 1;
    return a->encoding < b->encoding ? -1 : a->encoding > b->encoding;
}

static int gak_elf_add_dynamic_relocation(const GakFormat *format,
                                          GakRelocationTable *tables,
                                          size_t *count, uint64_t address,
                                          uint64_t size, uint64_t entry_size,
                                          int encoding) {
    if (!size) return 1;
    if (size > 16u * 1024u * 1024u) {
        gak_format_fail("ELF relocation table exceeds 16 MiB"); return 0;
    }
    uint64_t offset;
    if (!gak_dependency_map(format, 0, address, size, &offset)) return 0;
    tables[(*count)++] = (GakRelocationTable){offset, size, entry_size, encoding};
    return 1;
}

static int gak_elf_relocation_tables(const GakFormat *format,
                                     GakRelocationTable *tables, size_t *count) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    unsigned width = format->bits == 32 ? 4 : 8;
    int big = format->big_endian != 0;
    for (uint64_t index = 0; index < format->sections; index++) {
        uint64_t at = format->section_table + index * format->section_stride;
        uint64_t kind = gak_number(bytes, at + 4, 4, big);
        if (kind != 4 && kind != 9 && kind != 19) continue;
        uint64_t offset = gak_number(bytes, at + (width == 4 ? 16 : 24), width, big);
        uint64_t size = gak_number(bytes, at + (width == 4 ? 20 : 32), width, big);
        uint64_t entry = gak_number(bytes, at + (width == 4 ? 36 : 56), width, big);
        if (size)
            tables[(*count)++] = (GakRelocationTable){offset, size, entry,
                                                        kind == 4 ? 1 : kind == 9 ? 0 : 2};
    }
    uint64_t dynamic_offset = 0, dynamic_size = 0;
    int dynamic_seen = 0;
    for (uint64_t index = 0; index < format->program_count; index++) {
        uint64_t at = format->program_table + index * format->program_stride;
        if (gak_number(bytes, at, 4, big) != 2) continue;
        dynamic_seen = 1;
        dynamic_offset = gak_number(bytes, at + (width == 4 ? 4 : 8), width, big);
        dynamic_size = gak_number(bytes, at + (width == 4 ? 16 : 32), width, big);
        break;
    }
    if (!dynamic_seen) return 1;
    if (!dynamic_size || dynamic_size > 1024u * 1024u ||
        dynamic_size % (2u * width)) {
        gak_format_fail("invalid ELF dynamic table size"); return 0;
    }
    if (!gak_span(length, dynamic_offset, dynamic_size)) {
        gak_format_fail("ELF dynamic table outside captured Source"); return 0;
    }
    static const uint64_t tags[] = {7, 8, 9, 17, 18, 19, 23, 2, 20, 36, 35, 37};
    uint64_t values[12] = {0};
    int seen[12] = {0};
    int terminated = 0;
    for (uint64_t index = 0; index < dynamic_size / (2u * width); index++) {
        uint64_t at = dynamic_offset + index * (2u * width);
        uint64_t tag = gak_number(bytes, at, width, big);
        if (!tag) { terminated = 1; break; }
        for (size_t field = 0; field < 12; field++) {
            if (tag != tags[field]) continue;
            if (seen[field]) {
                gak_format_fail("duplicate ELF relocation dynamic tag"); return 0;
            }
            seen[field] = 1;
            values[field] = gak_number(bytes, at + width, width, big);
            break;
        }
    }
    if (!terminated) {
        gak_format_fail("ELF dynamic table has no DT_NULL terminator"); return 0;
    }
    if (seen[0] || seen[1] || seen[2]) {
        if (!seen[0] || !seen[1] || !seen[2]) {
            gak_format_fail("incomplete ELF dynamic relocation table"); return 0;
        }
        if (!gak_elf_add_dynamic_relocation(format, tables, count,
                                            values[0], values[1], values[2], 1)) return 0;
    }
    if (seen[3] || seen[4] || seen[5]) {
        if (!seen[3] || !seen[4] || !seen[5]) {
            gak_format_fail("incomplete ELF dynamic relocation table"); return 0;
        }
        if (!gak_elf_add_dynamic_relocation(format, tables, count,
                                            values[3], values[4], values[5], 0)) return 0;
    }
    if (seen[6] || seen[7] || seen[8]) {
        if (!seen[6] || !seen[7] || !seen[8]) {
            gak_format_fail("incomplete ELF PLT relocation table"); return 0;
        }
        int encoding = values[8] == 7 ? 1 : values[8] == 17 ? 0 : -1;
        if (encoding < 0) { gak_format_fail("invalid ELF DT_PLTREL type"); return 0; }
        if (!gak_elf_add_dynamic_relocation(format, tables, count,
                                            values[6], values[7],
                                            width * (encoding ? 3u : 2u), encoding)) return 0;
    }
    if (seen[9] || seen[10] || seen[11]) {
        if (!seen[9] || !seen[10] || !seen[11]) {
            gak_format_fail("incomplete ELF RELR dynamic table"); return 0;
        }
        if (!gak_elf_add_dynamic_relocation(format, tables, count,
                                            values[9], values[10], values[11], 2)) return 0;
    }
    return 1;
}

static int gak_elf_relocation_scan(const GakFormat *format, int64_t selected,
                                   GakRelocationSelection *result) {
    size_t capacity = (size_t)format->sections + 4u;
    GakRelocationTable *tables = malloc(capacity * sizeof(*tables));
    if (!tables) { gak_format_fail("native allocation failed"); return 0; }
    size_t count = 0;
    if (!gak_elf_relocation_tables(format, tables, &count)) goto failed;
    qsort(tables, count, sizeof(*tables), gak_relocation_table_compare);
    size_t unique = 0;
    for (size_t index = 0; index < count; index++) {
        GakRelocationTable table = tables[index];
        if (unique && tables[unique - 1].offset == table.offset &&
            tables[unique - 1].size == table.size &&
            tables[unique - 1].entry_size == table.entry_size &&
            tables[unique - 1].encoding == table.encoding) continue;
        tables[unique++] = table;
    }
    count = unique;
    for (size_t index = 1; index < count; index++) {
        uint64_t previous_end = tables[index - 1].offset + tables[index - 1].size;
        if (previous_end < tables[index - 1].offset) {
            gak_format_fail("ELF relocation table range overflow"); goto failed;
        }
        if (previous_end > tables[index].offset) {
            gak_format_fail("overlapping ELF relocation tables"); goto failed;
        }
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    unsigned width = format->bits == 32 ? 4 : 8;
    int big = format->big_endian != 0;
    uint64_t total_bytes = 0, total_entries = 0;
    for (size_t table_index = 0; table_index < count; table_index++) {
        GakRelocationTable table = tables[table_index];
        uint64_t expected = width * (table.encoding == 2 ? 1u :
                                     table.encoding == 1 ? 3u : 2u);
        if (table.entry_size != expected || table.size % expected) {
            gak_format_fail("invalid ELF relocation entry size"); goto failed;
        }
        uint64_t entries = table.size / expected;
        if (table.size > 16u * 1024u * 1024u - total_bytes ||
            entries > 100000u - total_entries) {
            gak_format_fail("ELF relocation limit exceeded"); goto failed;
        }
        total_bytes += table.size;
        total_entries += entries;
        if (!gak_span(length, table.offset, table.size)) {
            gak_format_fail("ELF relocation table outside captured Source"); goto failed;
        }
        if (table.encoding == 2) {
            if (format->file_type != 2 && format->file_type != 3) {
                gak_format_fail("ELF RELR requires ET_EXEC or ET_DYN"); goto failed;
            }
            uint64_t next = 0;
            int have_next = 0;
            for (uint64_t index = 0; index < table.size / width; index++) {
                uint64_t entry = gak_number(bytes, table.offset + index * width,
                                            width, big);
                if (!(entry & 1u)) {
                    if (entry % width) {
                        gak_format_fail("unaligned ELF RELR address"); goto failed;
                    }
                    if (entry > UINT64_MAX - width) {
                        gak_format_fail("ELF RELR address overflow"); goto failed;
                    }
                    next = entry + width;
                    have_next = 1;
                    if (!gak_relocation_emit(result, selected, entry, 0, 0, 0,
                                             0, 1)) goto failed;
                } else {
                    if (!have_next) {
                        gak_format_fail("ELF RELR bitmap without address"); goto failed;
                    }
                    for (unsigned bit = 1; bit < width * 8u; bit++) {
                        if (!(entry & ((uint64_t)1 << bit))) continue;
                        uint64_t delta = (uint64_t)(bit - 1u) * width;
                        if (next > UINT64_MAX - delta) {
                            gak_format_fail("ELF RELR address overflow"); goto failed;
                        }
                        uint64_t address = next + delta;
                        if (width == 4 && address > UINT32_MAX) {
                            gak_format_fail("ELF RELR address outside ELF32 space"); goto failed;
                        }
                        if (!gak_relocation_emit(result, selected, address, 0, 0,
                                                 0, 0, 1)) goto failed;
                    }
                    uint64_t delta = (uint64_t)(width * 8u - 1u) * width;
                    if (next > UINT64_MAX - delta) {
                        gak_format_fail("ELF RELR address overflow"); goto failed;
                    }
                    next += delta;
                }
            }
            continue;
        }
        for (uint64_t index = 0; index < table.size / expected; index++) {
            uint64_t at = table.offset + index * expected;
            uint64_t address = gak_number(bytes, at, width, big);
            uint64_t info = gak_number(bytes, at + width, width, big);
            uint64_t kind = width == 4 ? info & 0xffu : (uint32_t)info;
            uint64_t symbol = width == 4 ? info >> 8 : info >> 32;
            int64_t addend = 0;
            if (table.encoding == 1) {
                uint64_t raw = gak_number(bytes, at + 2u * width, width, big);
                addend = width == 4 ? (int64_t)(int32_t)(uint32_t)raw : (int64_t)raw;
            }
            if (kind && !gak_relocation_emit(result, selected, address, kind,
                                             symbol, addend, table.encoding == 1,
                                             0)) goto failed;
        }
    }
    free(tables);
    return 1;
failed:
    free(tables);
    return 0;
}

static int gak_relocation_scan(const GakFormat *format, int64_t selected,
                                GakRelocationSelection *result) {
    return format->kind == 1
        ? gak_pe_relocation_scan(format, selected, result)
        : gak_elf_relocation_scan(format, selected, result);
}

const void *gak_native_formats_relocation_location(const void *value) {
    const GakFormat *format = value;
    if (!format) { gak_format_fail("invalid Format"); return NULL; }
    if (format->kind == 1) return &text_rva;
    if (format->file_type == 1) return &text_section_offset;
    if (format->file_type == 2 || format->file_type == 3) return &text_va;
    return &text_unknown;
}

int64_t gak_native_formats_relocation_count(const void *value) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakRelocationSelection result = {0};
    if (!gak_relocation_scan(value, -1, &result)) return -1;
    return (int64_t)result.count;
}

int64_t gak_native_formats_relocation_number(const void *value, int64_t index,
                                              int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    if (index < 0) { gak_format_fail("relocation index out of range"); return -1; }
    GakRelocationSelection result = {0};
    if (!gak_relocation_scan(value, index, &result)) return -1;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("relocation index out of range"); return -1;
    }
    const GakFormat *format = value;
    if (part == 0 && format->kind != 1) {
        gak_format_fail("relocation_rva requires a PE image"); return -1;
    }
    if ((part == 1 || part == 2) && result.relr) {
        gak_format_fail(part == 1 ? "RELR relocation has no raw type code"
                                  : "RELR relocation has no symbol index"); return -1;
    }
    if (part == 2 && format->kind == 1) {
        gak_format_fail("ELF relocation expected"); return -1;
    }
    if (part == 3 && !result.has_addend) {
        gak_format_fail("relocation has no explicit addend"); return -1;
    }
    return part == 0 ? (int64_t)result.address
         : part == 1 ? (int64_t)result.kind
         : part == 2 ? (int64_t)result.symbol : result.addend;
}

void *gak_native_formats_relocation_text(const void *value, int64_t index,
                                          int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("relocation index out of range"); return NULL; }
    GakRelocationSelection result = {0};
    if (!gak_relocation_scan(value, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("relocation index out of range"); return NULL;
    }
    const GakFormat *format = value;
    const char *label = "unknown";
    if (result.relr) label = "RELR_RELATIVE";
    else if (format->kind == 1)
        label = result.kind == 1 ? "HIGH" : result.kind == 2 ? "LOW"
              : result.kind == 3 ? "HIGHLOW" : result.kind == 4 ? "HIGHADJ"
              : result.kind == 10 ? "DIR64" : "unknown";
    else if (format->machine == 62) {
        static const char *x86_64_labels[] = {
            "unknown", "R_X86_64_64", "R_X86_64_PC32", "R_X86_64_GOT32",
            "R_X86_64_PLT32", "R_X86_64_COPY", "R_X86_64_GLOB_DAT",
            "R_X86_64_JUMP_SLOT", "R_X86_64_RELATIVE", "R_X86_64_GOTPCREL",
            "R_X86_64_32", "R_X86_64_32S"
        };
        if (result.kind < sizeof(x86_64_labels) / sizeof(x86_64_labels[0]))
            label = x86_64_labels[result.kind];
    }
    const char *location = format->file_type == 1 ? "section_offset"
                           : format->file_type == 2 || format->file_type == 3
                           ? "va" : "unknown";
    char text[96];
    int size = part == 0
        ? snprintf(text, sizeof(text), "0x%llx", (unsigned long long)result.address)
        : part == 1
        ? snprintf(text, sizeof(text), "%s", label)
        : format->kind == 1
        ? snprintf(text, sizeof(text), "%s @ 0x%llx", label,
                   (unsigned long long)result.address)
        : snprintf(text, sizeof(text), "%s @ %s 0x%llx", label, location,
                   (unsigned long long)result.address);
    if (size < 0 || (size_t)size >= sizeof(text)) {
        gak_format_fail("invalid relocation text"); return NULL;
    }
    return gak_format_box(text, (size_t)size);
}

static void *gak_dependency_text(const uint8_t *raw, size_t length) {
    if (length > 4096 || length > (SIZE_MAX - 8) / 4) {
        gak_format_fail("dependency name exceeds native limit"); return NULL;
    }
    size_t escaped = 0;
    for (size_t index = 0; index < length; index++)
        escaped += raw[index] >= 0x20 && raw[index] <= 0x7e ? 1u : 4u;
    if (escaped > 64u * 1024u * 1024u - 8u ||
        format_memory > 64u * 1024u * 1024u - 8u - escaped) {
        gak_format_fail("format memory limit"); return NULL;
    }
    uint8_t *box = malloc(escaped + 8);
    if (!box) { gak_format_fail("native allocation failed"); return NULL; }
    uint64_t wide = (uint64_t)escaped;
    memcpy(box, &wide, 8);
    static const char digits[] = "0123456789abcdef";
    size_t cursor = 8;
    for (size_t index = 0; index < length; index++) {
        uint8_t byte = raw[index];
        if (byte >= 0x20 && byte <= 0x7e) box[cursor++] = byte;
        else {
            box[cursor++] = '\\'; box[cursor++] = 'x';
            box[cursor++] = digits[byte >> 4]; box[cursor++] = digits[byte & 15];
        }
    }
    format_memory += escaped + 8;
    return box;
}

static void gak_dependency_text_free(void *box) {
    uint64_t length;
    memcpy(&length, box, 8);
    format_memory -= (size_t)length + 8;
    free(box);
}

typedef struct {
    uint64_t count;
    uint64_t offset;
    uint64_t size;
    uint64_t timestamp;
    uint64_t kind;
    uint64_t age;
    const uint8_t *guid;
    const uint8_t *path;
    size_t path_length;
    int has_pdb;
} GakDebugSelection;

static int gak_pe_debug_scan(const GakFormat *format, int64_t selected,
                             GakDebugSelection *result) {
    if (format->kind != 1) {
        gak_format_fail("PE debug entries require a PE image"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t directory_offset = (format->bits == 32 ? 96 : 112) + 48;
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (gak_number(bytes, optional + count_offset, 4, 0) < 7) return 1;
    if (optional_size < directory_offset + 8) {
        gak_format_fail("PE debug directory lies outside optional header"); return 0;
    }
    uint64_t directory_rva = gak_number(bytes, optional + directory_offset, 4, 0);
    uint64_t directory_size = gak_number(bytes, optional + directory_offset + 4, 4, 0);
    if (!directory_rva && !directory_size) return 1;
    if (!directory_rva || !directory_size) {
        gak_format_fail("incomplete PE debug directory"); return 0;
    }
    if (directory_size > 16u * 1024u * 1024u) {
        gak_format_fail("PE debug directory exceeds 16 MiB"); return 0;
    }
    if (directory_size % 28u) {
        gak_format_fail("PE debug directory has a partial entry"); return 0;
    }
    if (directory_size / 28u > 4096u) {
        gak_format_fail("PE debug directory exceeds 4096 entries"); return 0;
    }
    uint64_t start;
    if (!gak_dependency_map(format, 1, directory_rva, directory_size, &start)) return 0;
    for (uint64_t index = 0; index < directory_size / 28u; index++) {
        uint64_t at = start + index * 28u;
        uint64_t timestamp = gak_number(bytes, at + 4u, 4, 0);
        uint64_t kind = gak_number(bytes, at + 12u, 4, 0);
        uint64_t size = gak_number(bytes, at + 16u, 4, 0);
        uint64_t data_rva = gak_number(bytes, at + 20u, 4, 0);
        uint64_t pointer = gak_number(bytes, at + 24u, 4, 0);
        if (size > 16u * 1024u * 1024u) {
            gak_format_fail("PE debug data exceeds 16 MiB"); return 0;
        }
        uint64_t offset = 0;
        if (size && pointer) {
            if (!gak_span(length, pointer, size)) {
                gak_format_fail("PE debug data outside captured Source"); return 0;
            }
            offset = pointer;
        } else if (size && data_rva) {
            if (!gak_dependency_map(format, 1, data_rva, size, &offset)) return 0;
        } else if (size) {
            gak_format_fail("PE debug entry has no data address"); return 0;
        }
        const uint8_t *guid = NULL;
        const uint8_t *path = NULL;
        size_t path_length = 0;
        uint64_t age = 0;
        int has_pdb = 0;
        if (kind == 2 && size >= 4 && memcmp(bytes + offset, "RSDS", 4) == 0) {
            if (size < 25) {
                gak_format_fail("truncated PE CodeView RSDS data"); return 0;
            }
            guid = bytes + offset + 4;
            age = gak_number(bytes, offset + 20, 4, 0);
            path = bytes + offset + 24;
            uint64_t available = size - 24;
            uint64_t scan = available < 4097u ? available : 4097u;
            while (path_length < scan && path[path_length]) path_length++;
            if (path_length == scan) {
                gak_format_fail(available > 4096u ? "PE PDB path exceeds 4096 bytes"
                                               : "unterminated PE PDB path"); return 0;
            }
            if (!path_length) {
                gak_format_fail("empty PE PDB path"); return 0;
            }
            if (path_length > 4096u) {
                gak_format_fail("PE PDB path exceeds 4096 bytes"); return 0;
            }
            has_pdb = 1;
        }
        if (selected >= 0 && (uint64_t)selected == index) {
            result->offset = offset;
            result->size = size;
            result->timestamp = timestamp;
            result->kind = kind;
            result->age = age;
            result->guid = guid;
            result->path = path;
            result->path_length = path_length;
            result->has_pdb = has_pdb;
        }
        result->count++;
    }
    return 1;
}

int64_t gak_native_formats_debug_count(const void *value) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakDebugSelection result = {0};
    if (!gak_pe_debug_scan(value, -1, &result)) return -1;
    return (int64_t)result.count;
}

int64_t gak_native_formats_debug_number(const void *value, int64_t index, int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    if (index < 0) { gak_format_fail("debug index out of range"); return -1; }
    GakDebugSelection result = {0};
    if (!gak_pe_debug_scan(value, index, &result)) return -1;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("debug index out of range"); return -1;
    }
    if (part == 3 && !result.has_pdb) {
        gak_format_fail("PE debug entry has no RSDS PDB data"); return -1;
    }
    uint64_t number = part == 0 ? result.kind : part == 1 ? result.timestamp
                    : part == 2 ? result.size : result.age;
    return (int64_t)number;
}

void *gak_native_formats_debug_text(const void *value, int64_t index, int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("debug index out of range"); return NULL; }
    GakDebugSelection result = {0};
    if (!gak_pe_debug_scan(value, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("debug index out of range"); return NULL;
    }
    if (part == 0) {
        const char *label = result.kind == 0 ? "unknown" : result.kind == 1 ? "coff"
                          : result.kind == 2 ? "codeview" : result.kind == 16 ? "repro" : "other";
        return gak_format_box(label, strlen(label));
    }
    if (!result.has_pdb) {
        gak_format_fail("PE debug entry has no RSDS PDB data"); return NULL;
    }
    if (part == 1) return gak_dependency_text(result.path, result.path_length);
    const uint8_t *guid = result.guid;
    char text[37];
    int size = snprintf(text, sizeof(text),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        (unsigned)gak_number(guid, 0, 4, 0),
                        (unsigned)gak_number(guid, 4, 2, 0),
                        (unsigned)gak_number(guid, 6, 2, 0),
                        guid[8], guid[9], guid[10], guid[11],
                        guid[12], guid[13], guid[14], guid[15]);
    if (size != 36) { gak_format_fail("invalid PE PDB GUID"); return NULL; }
    return gak_format_box(text, 36);
}

void *gak_native_formats_debug_data(const void *value, int64_t index) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("debug index out of range"); return NULL; }
    GakDebugSelection result = {0};
    if (!gak_pe_debug_scan(value, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("debug index out of range"); return NULL;
    }
    if (!result.size) { gak_format_fail("PE debug entry has no data"); return NULL; }
    return gak_format_range(value, result.offset, result.offset + result.size, 0, 0);
}

static int gak_pe_text(const GakFormat *format, uint64_t rva, uint64_t max_length,
                       const uint8_t **name, size_t *name_length) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    uint64_t text_at;
    if (!gak_dependency_map(format, 1, rva, 1, &text_at)) return 0;
    uint64_t available = 0;
    if (format->headers_available && rva < format->headers_size) {
        available = format->headers_size - rva;
    } else {
        for (uint64_t section = 0; section < format->sections; section++) {
            uint64_t header = format->section_table + section * 40u;
            uint64_t start = gak_number(bytes, header + 12, 4, 0);
            uint64_t size = gak_number(bytes, header + 16, 4, 0);
            if (rva >= start && rva - start < size) {
                available = size - (rva - start);
                break;
            }
        }
    }
    if (!available) { gak_format_fail("PE text has no file-backed bytes"); return 0; }
    if (available > max_length) available = max_length;
    if (available > length - text_at) available = length - text_at;
    uint64_t text_size = 0;
    while (text_size < available && bytes[text_at + text_size]) text_size++;
    if (text_size == available) { gak_format_fail("unterminated PE text"); return 0; }
    if (!text_size) { gak_format_fail("empty PE text"); return 0; }
    *name = bytes + text_at;
    *name_length = (size_t)text_size;
    return 1;
}

static int gak_pe_dependencies(const GakFormat *format, int64_t selected,
                                uint64_t *count, const uint8_t **name,
                                size_t *name_length) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t import_offset = format->bits == 32 ? 104 : 120;
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (gak_number(bytes, optional + count_offset, 4, 0) < 2) {
        *count = 0; return 1;
    }
    if (optional_size < import_offset + 8) {
        gak_format_fail("PE import directory lies outside optional header"); return 0;
    }
    uint64_t directory_rva = gak_number(bytes, optional + import_offset, 4, 0);
    uint64_t directory_size = gak_number(bytes, optional + import_offset + 4, 4, 0);
    if (!directory_rva && !directory_size) { *count = 0; return 1; }
    if (!directory_rva || !directory_size) {
        gak_format_fail("incomplete PE import directory"); return 0;
    }
    for (uint64_t index = 0; index <= 4096; index++) {
        uint64_t relative = index * 20u;
        if (relative + 20u > directory_size) {
            gak_format_fail("PE import directory has no null descriptor"); return 0;
        }
        uint64_t at;
        if (!gak_dependency_map(format, 1, directory_rva + relative, 20, &at)) return 0;
        int empty = 1;
        for (size_t byte = 0; byte < 20; byte++) empty &= bytes[at + byte] == 0;
        if (empty) { *count = index; return 1; }
        if (index == 4096) {
            gak_format_fail("PE import directory exceeds 4096 descriptors"); return 0;
        }
        uint64_t lookup_rva = gak_number(bytes, at, 4, 0);
        uint64_t library_rva = gak_number(bytes, at + 12, 4, 0);
        uint64_t iat_rva = gak_number(bytes, at + 16, 4, 0);
        if (!library_rva || (!lookup_rva && !iat_rva)) {
            gak_format_fail("PE import descriptor lacks a library or lookup table"); return 0;
        }
        const uint8_t *text;
        size_t text_size;
        if (!gak_pe_text(format, library_rva, 1024, &text, &text_size)) return 0;
        if (selected >= 0 && (uint64_t)selected == index) {
            *name = text;
            *name_length = text_size;
        }
    }
    gak_format_fail("PE import directory exceeds 4096 descriptors");
    return 0;
}

typedef struct {
    uint64_t count;
    const uint8_t *library;
    size_t library_length;
    const uint8_t *symbol;
    size_t symbol_length;
    uint16_t ordinal;
    int is_ordinal;
} GakImportSelection;

static int gak_pe_import_directory(const GakFormat *format, int delayed,
                                    uint64_t *rva, uint64_t *size) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t directory_offset = delayed
        ? (format->bits == 32 ? 200 : 216)
        : (format->bits == 32 ? 104 : 120);
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (gak_number(bytes, optional + count_offset, 4, 0) < (delayed ? 14u : 2u)) {
        *rva = 0; *size = 0; return 1;
    }
    if (optional_size < directory_offset + 8) {
        gak_format_fail(delayed ? "PE delay import directory lies outside optional header"
                                : "PE import directory lies outside optional header");
        return 0;
    }
    *rva = gak_number(bytes, optional + directory_offset, 4, 0);
    *size = gak_number(bytes, optional + directory_offset + 4, 4, 0);
    if (!!*rva != !!*size) {
        gak_format_fail(delayed ? "incomplete PE delay import directory"
                                : "incomplete PE import directory");
        return 0;
    }
    return 1;
}

static int gak_pe_delay_rva(const GakFormat *format, uint64_t address,
                            int va_based, uint64_t *rva) {
    if (!va_based) { *rva = address; return 1; }
    if (!format->image_base_width) {
        gak_format_fail("PE image base is unavailable"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t image_base = gak_number(bytes, format->image_base_at,
                                     (unsigned)format->image_base_width, 0);
    if (address < image_base) {
        gak_format_fail("PE delay import VA is below image base"); return 0;
    }
    *rva = address - image_base;
    return 1;
}

static int gak_pe_delay_dependencies(const GakFormat *format, int64_t selected,
                                      uint64_t *count, const uint8_t **name,
                                      size_t *name_length) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t directory_rva, directory_size;
    if (!gak_pe_import_directory(format, 1, &directory_rva, &directory_size)) return 0;
    if (!directory_rva) { *count = 0; return 1; }
    for (uint64_t index = 0; index <= 4096; index++) {
        uint64_t relative = index * 32u;
        if (relative + 32u > directory_size) {
            gak_format_fail("PE delay import directory has no null descriptor"); return 0;
        }
        uint64_t at;
        if (!gak_dependency_map(format, 1, directory_rva + relative, 32, &at)) return 0;
        int empty = 1;
        for (size_t byte = 0; byte < 32; byte++) empty &= bytes[at + byte] == 0;
        if (empty) { *count = index; return 1; }
        if (index == 4096) {
            gak_format_fail("PE delay import directory exceeds 4096 descriptors"); return 0;
        }
        uint64_t attributes = gak_number(bytes, at, 4, 0);
        if (attributes & ~1u) {
            gak_format_fail("PE delay import descriptor has reserved attribute bits");
            return 0;
        }
        uint64_t library_address = gak_number(bytes, at + 4, 4, 0);
        uint64_t lookup_address = gak_number(bytes, at + 16, 4, 0);
        if (!library_address || !lookup_address) {
            gak_format_fail("PE delay import descriptor lacks a library or name table");
            return 0;
        }
        uint64_t library_rva, lookup_rva;
        int va_based = attributes == 0;
        if (!gak_pe_delay_rva(format, library_address, va_based, &library_rva) ||
            !gak_pe_delay_rva(format, lookup_address, va_based, &lookup_rva)) return 0;
        (void)lookup_rva;
        const uint8_t *text;
        size_t text_size;
        if (!gak_pe_text(format, library_rva, 1024, &text, &text_size)) return 0;
        if (selected >= 0 && (uint64_t)selected == index) {
            *name = text;
            *name_length = text_size;
        }
    }
    gak_format_fail("PE delay import directory exceeds 4096 descriptors");
    return 0;
}

static int gak_pe_import_scan(const GakFormat *format, int delayed,
                              int64_t selected, GakImportSelection *result) {
    if (format->kind != 1) {
        gak_format_fail(delayed ? "PE delay imports require a PE image"
                                : "PE imports require a PE image");
        return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t directory_rva, directory_size;
    if (!gak_pe_import_directory(format, delayed, &directory_rva, &directory_size)) return 0;
    if (!directory_rva) return 1;
    uint64_t descriptor_count = 0;
    const uint8_t *unused_name = NULL;
    size_t unused_length = 0;
    if (!(delayed
              ? gak_pe_delay_dependencies(format, -1, &descriptor_count,
                                           &unused_name, &unused_length)
              : gak_pe_dependencies(format, -1, &descriptor_count,
                                    &unused_name, &unused_length))) return 0;
    (void)descriptor_count;
    uint64_t descriptor_size = delayed ? 32 : 20;
    unsigned thunk_width = format->bits == 32 ? 4 : 8;
    uint64_t ordinal_flag = (uint64_t)1 << (thunk_width * 8 - 1);
    for (uint64_t descriptor = 0; descriptor <= 4096; descriptor++) {
        uint64_t relative = descriptor * descriptor_size;
        if (relative + descriptor_size > directory_size) {
            gak_format_fail(delayed ? "PE delay import directory has no null descriptor"
                                    : "PE import directory has no null descriptor");
            return 0;
        }
        uint64_t at;
        if (!gak_dependency_map(format, 1, directory_rva + relative,
                                descriptor_size, &at)) return 0;
        int empty = 1;
        for (uint64_t byte = 0; byte < descriptor_size; byte++)
            empty &= bytes[at + byte] == 0;
        if (empty) return 1;
        if (descriptor == 4096) {
            gak_format_fail(delayed ? "PE delay import directory exceeds 4096 descriptors"
                                    : "PE import directory exceeds 4096 descriptors");
            return 0;
        }
        uint64_t lookup_rva, library_rva;
        int va_based = 0;
        if (delayed) {
            uint64_t attributes = gak_number(bytes, at, 4, 0);
            if (attributes & ~1u) {
                gak_format_fail("PE delay import descriptor has reserved attribute bits");
                return 0;
            }
            uint64_t library_address = gak_number(bytes, at + 4, 4, 0);
            uint64_t lookup_address = gak_number(bytes, at + 16, 4, 0);
            if (!library_address || !lookup_address) {
                gak_format_fail("PE delay import descriptor lacks a library or name table");
                return 0;
            }
            va_based = attributes == 0;
            if (!gak_pe_delay_rva(format, library_address, va_based, &library_rva) ||
                !gak_pe_delay_rva(format, lookup_address, va_based, &lookup_rva)) return 0;
        } else {
            lookup_rva = gak_number(bytes, at, 4, 0);
            library_rva = gak_number(bytes, at + 12, 4, 0);
            uint64_t iat_rva = gak_number(bytes, at + 16, 4, 0);
            if (!library_rva || (!lookup_rva && !iat_rva)) {
                gak_format_fail("PE import descriptor lacks a library or lookup table");
                return 0;
            }
            if (!lookup_rva) lookup_rva = iat_rva;
        }
        const uint8_t *library;
        size_t library_length;
        if (!gak_pe_text(format, library_rva, 1024, &library, &library_length)) return 0;
        for (uint64_t symbol_index = 0; symbol_index <= 10000; symbol_index++) {
            uint64_t delta = symbol_index * thunk_width;
            if (lookup_rva > UINT64_MAX - delta) {
                gak_format_fail("PE import lookup RVA overflow"); return 0;
            }
            uint64_t thunk_at;
            if (!gak_dependency_map(format, 1, lookup_rva + delta,
                                    thunk_width, &thunk_at)) return 0;
            uint64_t raw = gak_number(bytes, thunk_at, thunk_width, 0);
            if (!raw) break;
            if (result->count >= 10000) {
                gak_format_fail("PE imports exceed 10000 symbols"); return 0;
            }
            const uint8_t *symbol = NULL;
            size_t symbol_length = 0;
            uint16_t ordinal = 0;
            int is_ordinal = raw & ordinal_flag ? 1 : 0;
            if (is_ordinal) {
                if (raw & ~(ordinal_flag | 0xffffu)) {
                    gak_format_fail("PE import ordinal has reserved bits set"); return 0;
                }
                ordinal = (uint16_t)(raw & 0xffffu);
            } else {
                uint64_t name_rva;
                if (!gak_pe_delay_rva(format, raw, va_based, &name_rva)) return 0;
                if (name_rva > UINT32_MAX) {
                    gak_format_fail("PE import name RVA outside PE address space"); return 0;
                }
                uint64_t hint_at;
                if (!gak_dependency_map(format, 1, name_rva, 2, &hint_at)) return 0;
                if (!gak_pe_text(format, name_rva + 2, 4096,
                                 &symbol, &symbol_length)) return 0;
            }
            if (selected >= 0 && (uint64_t)selected == result->count) {
                result->library = library;
                result->library_length = library_length;
                result->symbol = symbol;
                result->symbol_length = symbol_length;
                result->ordinal = ordinal;
                result->is_ordinal = is_ordinal;
            }
            result->count++;
            if (symbol_index == 10000) {
                gak_format_fail("PE import lookup table has no null entry"); return 0;
            }
        }
    }
    gak_format_fail(delayed ? "PE delay import directory exceeds 4096 descriptors"
                            : "PE import directory exceeds 4096 descriptors");
    return 0;
}

int64_t gak_native_formats_import_count(const void *value, int delayed) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakImportSelection result = {0};
    if (!gak_pe_import_scan(value, delayed, -1, &result)) return -1;
    return (int64_t)result.count;
}

void *gak_native_formats_import_text(const void *value, int64_t index,
                                      int delayed, int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("import index out of range"); return NULL; }
    GakImportSelection result = {0};
    if (!gak_pe_import_scan(value, delayed, index, &result)) return NULL;
    if ((uint64_t)index >= result.count || !result.library) {
        gak_format_fail("import index out of range"); return NULL;
    }
    if (part == 0) return gak_dependency_text(result.library, result.library_length);
    if (part == 2) return (void *)(result.is_ordinal ? &text_ordinal : &text_name);
    char ordinal[8];
    const uint8_t *symbol = result.symbol;
    size_t symbol_length = result.symbol_length;
    if (result.is_ordinal) {
        int length = snprintf(ordinal, sizeof(ordinal), "#%u", (unsigned)result.ordinal);
        if (length < 0 || (size_t)length >= sizeof(ordinal)) {
            gak_format_fail("invalid PE import ordinal"); return NULL;
        }
        symbol = (const uint8_t *)ordinal;
        symbol_length = (size_t)length;
    }
    if (part == 1) return gak_dependency_text(symbol, symbol_length);
    if (part != 3) { gak_format_fail("invalid PE import field"); return NULL; }
    void *library_box = gak_dependency_text(result.library, result.library_length);
    if (!library_box) return NULL;
    void *symbol_box = gak_dependency_text(symbol, symbol_length);
    if (!symbol_box) {
        gak_dependency_text_free(library_box);
        return NULL;
    }
    uint64_t library_size = *(uint64_t *)library_box;
    uint64_t symbol_size = *(uint64_t *)symbol_box;
    if (library_size > SIZE_MAX - symbol_size - 1) {
        gak_dependency_text_free(library_box);
        gak_dependency_text_free(symbol_box);
        gak_format_fail("PE import summary too large"); return NULL;
    }
    size_t total = (size_t)(library_size + symbol_size + 1);
    char *joined = malloc(total);
    if (!joined) {
        gak_dependency_text_free(library_box);
        gak_dependency_text_free(symbol_box);
        gak_format_fail("native allocation failed"); return NULL;
    }
    memcpy(joined, (uint8_t *)library_box + 8, (size_t)library_size);
    joined[library_size] = '!';
    memcpy(joined + library_size + 1, (uint8_t *)symbol_box + 8,
           (size_t)symbol_size);
    gak_dependency_text_free(library_box);
    gak_dependency_text_free(symbol_box);
    void *summary = gak_format_box(joined, total);
    free(joined);
    return summary;
}

typedef struct {
    const uint8_t *text;
    size_t length;
    int32_t next;
} GakExportName;

typedef struct {
    uint64_t count;
    const uint8_t *name;
    size_t name_length;
    int named;
    uint64_t ordinal;
    uint64_t rva;
    const uint8_t *forwarder;
    size_t forwarder_length;
    int is_forwarder;
} GakExportSelection;

static int gak_pe_export_scan(const GakFormat *format, int64_t selected,
                              GakExportSelection *result) {
    if (format->kind != 1) {
        gak_format_fail("PE exports require a PE image"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t pe_offset = gak_number(bytes, 0x3c, 4, 0);
    uint64_t optional = pe_offset + 24;
    uint64_t optional_size = gak_number(bytes, pe_offset + 20, 2, 0);
    uint64_t count_offset = format->bits == 32 ? 92 : 108;
    uint64_t directory_offset = format->bits == 32 ? 96 : 112;
    if (optional_size < count_offset + 4) {
        gak_format_fail("PE optional header has no data-directory count"); return 0;
    }
    if (!gak_number(bytes, optional + count_offset, 4, 0)) return 1;
    if (optional_size < directory_offset + 8) {
        gak_format_fail("PE export directory lies outside optional header"); return 0;
    }
    uint64_t directory_rva = gak_number(bytes, optional + directory_offset, 4, 0);
    uint64_t directory_size = gak_number(bytes, optional + directory_offset + 4, 4, 0);
    if (!directory_rva && !directory_size) return 1;
    if (!directory_rva || !directory_size) {
        gak_format_fail("incomplete PE export directory"); return 0;
    }
    if (directory_size < 40) {
        gak_format_fail("PE export directory is shorter than its header"); return 0;
    }
    uint64_t directory_end = directory_rva + directory_size;
    if (directory_end > (uint64_t)UINT32_MAX + 1u) {
        gak_format_fail("PE export directory outside PE address space"); return 0;
    }
    uint64_t header;
    if (!gak_dependency_map(format, 1, directory_rva, 40, &header)) return 0;
    uint64_t base = gak_number(bytes, header + 16, 4, 0);
    uint64_t address_count = gak_number(bytes, header + 20, 4, 0);
    uint64_t name_count = gak_number(bytes, header + 24, 4, 0);
    if (address_count > 10000 || name_count > 10000) {
        gak_format_fail("PE export table exceeds symbol limits"); return 0;
    }
    if (name_count && !address_count) {
        gak_format_fail("PE export names have no address table"); return 0;
    }
    uint64_t address_rva = gak_number(bytes, header + 28, 4, 0);
    uint64_t name_rva = gak_number(bytes, header + 32, 4, 0);
    uint64_t ordinal_rva = gak_number(bytes, header + 36, 4, 0);
    uint64_t address_table = 0, name_table = 0, ordinal_table = 0;
    if (address_count && !gak_dependency_map(format, 1, address_rva,
                                             address_count * 4u, &address_table)) return 0;
    if (name_count &&
        (!gak_dependency_map(format, 1, name_rva, name_count * 4u, &name_table) ||
         !gak_dependency_map(format, 1, ordinal_rva, name_count * 2u,
                             &ordinal_table))) return 0;
    int32_t *heads = NULL, *tails = NULL;
    GakExportName *names = NULL;
    if (address_count) {
        heads = malloc((size_t)address_count * sizeof(*heads));
        tails = malloc((size_t)address_count * sizeof(*tails));
        if (!heads || !tails) {
            gak_format_fail("native allocation failed"); goto failed;
        }
        for (uint64_t index = 0; index < address_count; index++)
            heads[index] = tails[index] = -1;
    }
    if (name_count) {
        names = calloc((size_t)name_count, sizeof(*names));
        if (!names) { gak_format_fail("native allocation failed"); goto failed; }
    }
    for (uint64_t index = 0; index < name_count; index++) {
        uint64_t text_rva = gak_number(bytes, name_table + index * 4u, 4, 0);
        uint64_t ordinal_index = gak_number(bytes, ordinal_table + index * 2u, 2, 0);
        if (ordinal_index >= address_count) {
            gak_format_fail("PE export name ordinal index out of range"); goto failed;
        }
        if (!gak_pe_text(format, text_rva, 4096,
                         &names[index].text, &names[index].length)) goto failed;
        names[index].next = -1;
        if (heads[ordinal_index] < 0) heads[ordinal_index] = (int32_t)index;
        else names[tails[ordinal_index]].next = (int32_t)index;
        tails[ordinal_index] = (int32_t)index;
    }
    for (uint64_t index = 0; index < address_count; index++) {
        uint64_t target_rva = gak_number(bytes, address_table + index * 4u, 4, 0);
        if (!target_rva) {
            if (heads[index] >= 0) {
                gak_format_fail("PE export name points to an empty address"); goto failed;
            }
            continue;
        }
        if (base > UINT32_MAX - index) {
            gak_format_fail("PE export ordinal outside u32 range"); goto failed;
        }
        uint64_t ordinal = base + index;
        const uint8_t *forwarder = NULL;
        size_t forwarder_length = 0;
        int is_forwarder = target_rva >= directory_rva && target_rva < directory_end;
        if (is_forwarder) {
            uint64_t available = directory_end - target_rva;
            if (available > 4096) available = 4096;
            if (!gak_pe_text(format, target_rva, available,
                             &forwarder, &forwarder_length)) goto failed;
        }
        int32_t name_index = heads[index];
        do {
            if (selected >= 0 && (uint64_t)selected == result->count) {
                result->named = name_index >= 0;
                result->name = name_index >= 0 ? names[name_index].text : NULL;
                result->name_length = name_index >= 0 ? names[name_index].length : 0;
                result->ordinal = ordinal;
                result->rva = target_rva;
                result->forwarder = forwarder;
                result->forwarder_length = forwarder_length;
                result->is_forwarder = is_forwarder;
            }
            result->count++;
            name_index = name_index >= 0 ? names[name_index].next : -1;
        } while (name_index >= 0);
    }
    free(heads); free(tails); free(names);
    return 1;
failed:
    free(heads); free(tails); free(names);
    return 0;
}

int64_t gak_native_formats_export_count(const void *value) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakExportSelection result = {0};
    if (!gak_pe_export_scan(value, -1, &result)) return -1;
    return (int64_t)result.count;
}

int64_t gak_native_formats_export_number(const void *value, int64_t index,
                                          int address) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    if (index < 0) { gak_format_fail("export index out of range"); return -1; }
    GakExportSelection result = {0};
    if (!gak_pe_export_scan(value, index, &result)) return -1;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("export index out of range"); return -1;
    }
    if (address && result.is_forwarder) {
        gak_format_fail("forwarded export has no direct address"); return -1;
    }
    return (int64_t)(address ? result.rva : result.ordinal);
}

static void *gak_export_name(const GakExportSelection *result) {
    if (result->named)
        return gak_dependency_text(result->name, result->name_length);
    char ordinal[32];
    int length = snprintf(ordinal, sizeof(ordinal), "#%llu",
                          (unsigned long long)result->ordinal);
    if (length < 0 || (size_t)length >= sizeof(ordinal)) {
        gak_format_fail("invalid PE export ordinal"); return NULL;
    }
    return gak_format_box(ordinal, (size_t)length);
}

static void *gak_export_target(const GakExportSelection *result) {
    if (result->is_forwarder)
        return gak_dependency_text(result->forwarder, result->forwarder_length);
    char address[32];
    int length = snprintf(address, sizeof(address), "0x%llx",
                          (unsigned long long)result->rva);
    if (length < 0 || (size_t)length >= sizeof(address)) {
        gak_format_fail("invalid PE export address"); return NULL;
    }
    return gak_format_box(address, (size_t)length);
}

void *gak_native_formats_export_text(const void *value, int64_t index, int part) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) { gak_format_fail("export index out of range"); return NULL; }
    GakExportSelection result = {0};
    if (!gak_pe_export_scan(value, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail("export index out of range"); return NULL;
    }
    if (part == 2) return (void *)(result.is_forwarder ? &text_forwarder : &text_rva);
    if (part == 0) return gak_export_name(&result);
    if (part == 1) return gak_export_target(&result);
    if (part != 3) { gak_format_fail("invalid PE export field"); return NULL; }
    void *name = gak_export_name(&result);
    if (!name) return NULL;
    void *target = gak_export_target(&result);
    if (!target) { gak_dependency_text_free(name); return NULL; }
    uint64_t name_size, target_size;
    memcpy(&name_size, name, 8);
    memcpy(&target_size, target, 8);
    char ordinal[32];
    int ordinal_length = result.named
        ? snprintf(ordinal, sizeof(ordinal), " (#%llu)",
                   (unsigned long long)result.ordinal) : 0;
    if (ordinal_length < 0 || (size_t)ordinal_length >= sizeof(ordinal)) {
        gak_dependency_text_free(name);
        gak_dependency_text_free(target);
        gak_format_fail("invalid PE export ordinal"); return NULL;
    }
    const char *connector = result.is_forwarder ? " -> " : " @ ";
    size_t connector_length = result.is_forwarder ? 4u : 3u;
    size_t total = (size_t)name_size + (size_t)ordinal_length + connector_length +
                   (size_t)target_size;
    char *joined = malloc(total);
    if (!joined) {
        gak_dependency_text_free(name);
        gak_dependency_text_free(target);
        gak_format_fail("native allocation failed"); return NULL;
    }
    size_t at = 0;
    memcpy(joined + at, (uint8_t *)name + 8, (size_t)name_size); at += (size_t)name_size;
    if (ordinal_length) {
        memcpy(joined + at, ordinal, (size_t)ordinal_length);
        at += (size_t)ordinal_length;
    }
    memcpy(joined + at, connector, connector_length); at += connector_length;
    memcpy(joined + at, (uint8_t *)target + 8, (size_t)target_size);
    gak_dependency_text_free(name);
    gak_dependency_text_free(target);
    void *summary = gak_format_box(joined, total);
    free(joined);
    return summary;
}

static int gak_elf_dependencies(const GakFormat *format, int64_t selected,
                                 uint64_t *count, const uint8_t **name,
                                 size_t *name_length) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    unsigned width = format->bits == 32 ? 4 : 8;
    int big = format->big_endian != 0;
    uint64_t dynamic_offset = 0, dynamic_size = 0;
    int found = 0;
    for (uint64_t index = 0; index < format->program_count; index++) {
        uint64_t at = format->program_table + index * format->program_stride;
        if (gak_number(bytes, at, 4, big) != 2) continue;
        found = 1;
        dynamic_offset = gak_number(bytes, at + (width == 4 ? 4 : 8), width, big);
        dynamic_size = gak_number(bytes, at + (width == 4 ? 16 : 32), width, big);
        break;
    }
    if (!found) { *count = 0; return 1; }
    uint64_t entry_size = width * 2u;
    if (!dynamic_size || dynamic_size > 1024u * 1024u ||
        dynamic_size % entry_size) {
        gak_format_fail("invalid ELF dynamic table size"); return 0;
    }
    if (!gak_span(length, dynamic_offset, dynamic_size)) {
        gak_format_fail("ELF dynamic table outside captured Source"); return 0;
    }
    uint64_t string_va = 0, string_size = 0, needed = 0;
    int have_string_va = 0, have_string_size = 0, terminated = 0;
    for (uint64_t index = 0; index < dynamic_size / entry_size; index++) {
        uint64_t at = dynamic_offset + index * entry_size;
        uint64_t tag = gak_number(bytes, at, width, big);
        uint64_t value = gak_number(bytes, at + width, width, big);
        if (!tag) { terminated = 1; break; }
        if (tag == 1) {
            if (needed == 10000) {
                gak_format_fail("ELF needed libraries exceed 10000"); return 0;
            }
            needed++;
        } else if (tag == 5) {
            if (have_string_va++) { gak_format_fail("duplicate ELF DT_STRTAB"); return 0; }
            string_va = value;
        } else if (tag == 10) {
            if (have_string_size++) { gak_format_fail("duplicate ELF DT_STRSZ"); return 0; }
            string_size = value;
        }
    }
    if (!terminated) { gak_format_fail("ELF dynamic table has no DT_NULL terminator"); return 0; }
    if (!needed) { *count = 0; return 1; }
    if (!have_string_va) { gak_format_fail("ELF needed libraries lack DT_STRTAB"); return 0; }
    if (!have_string_size) { gak_format_fail("ELF needed libraries lack DT_STRSZ"); return 0; }
    if (!string_size || string_size > 16u * 1024u * 1024u) {
        gak_format_fail("invalid ELF dynamic string table size"); return 0;
    }
    uint64_t string_at;
    if (!gak_dependency_map(format, 0, string_va, string_size, &string_at)) return 0;
    uint64_t item = 0;
    for (uint64_t index = 0; index < dynamic_size / entry_size; index++) {
        uint64_t at = dynamic_offset + index * entry_size;
        uint64_t tag = gak_number(bytes, at, width, big);
        if (!tag) break;
        if (tag != 1) continue;
        uint64_t offset = gak_number(bytes, at + width, width, big);
        if (offset >= string_size) {
            gak_format_fail("ELF needed name offset out of range"); return 0;
        }
        uint64_t available = string_size - offset;
        if (available > 4097) available = 4097;
        uint64_t text_size = 0;
        while (text_size < available && bytes[string_at + offset + text_size]) text_size++;
        if (text_size == available) {
            gak_format_fail("unterminated or oversized ELF needed name"); return 0;
        }
        if (!text_size || text_size > 4096) {
            gak_format_fail("empty or oversized ELF needed name"); return 0;
        }
        if (selected >= 0 && (uint64_t)selected == item) {
            *name = bytes + string_at + offset;
            *name_length = (size_t)text_size;
        }
        item++;
    }
    *count = needed;
    return 1;
}

static int gak_dependency_scan(const GakFormat *format, int mode,
                                int64_t selected, uint64_t *count,
                                const uint8_t **name, size_t *name_length) {
    if (mode == 1 && format->kind != 2) {
        gak_format_fail("ELF needed libraries require an ELF image"); return 0;
    }
    if (mode == 2) {
        if (format->kind != 1) {
            gak_format_fail("PE delay dependencies require a PE image"); return 0;
        }
        return gak_pe_delay_dependencies(format, selected, count, name, name_length);
    }
    return format->kind == 1
        ? gak_pe_dependencies(format, selected, count, name, name_length)
        : gak_elf_dependencies(format, selected, count, name, name_length);
}

int64_t gak_native_formats_dependency_count(const void *value, int mode) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    uint64_t count = 0;
    const uint8_t *name = NULL;
    size_t length = 0;
    if (!gak_dependency_scan(value, mode, -1, &count, &name, &length)) return -1;
    return (int64_t)count;
}

void *gak_native_formats_dependency_name(const void *value, int64_t index,
                                          int mode) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) {
        gak_format_fail(mode == 1 ? "needed library index out of range"
                              : mode == 2 ? "delay dependency index out of range"
                                          : "dependency index out of range");
        return NULL;
    }
    uint64_t count = 0;
    const uint8_t *name = NULL;
    size_t length = 0;
    if (!gak_dependency_scan(value, mode, index, &count, &name, &length)) return NULL;
    if ((uint64_t)index >= count || !name) {
        gak_format_fail(mode == 1 ? "needed library index out of range"
                              : mode == 2 ? "delay dependency index out of range"
                                          : "dependency index out of range");
        return NULL;
    }
    return gak_dependency_text(name, length);
}

typedef struct {
    uint64_t count;
    const uint8_t *name;
    size_t name_length;
    uint64_t address;
    uint64_t size;
    uint16_t section;
    uint8_t binding;
    uint8_t kind;
    uint8_t visibility;
} GakSymbolSelection;

static int gak_elf_symbol_hash_count(const GakFormat *format, uint64_t hash_va,
                                     int gnu, uint64_t *count) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    int big = format->big_endian != 0;
    uint64_t at;
    if (!gak_dependency_map(format, 0, hash_va, gnu ? 16 : 8, &at)) return 0;
    uint64_t buckets = gak_number(bytes, at, 4, big);
    if (!gnu) {
        uint64_t chains = gak_number(bytes, at + 4, 4, big);
        if (buckets > 100000 || chains > 100000) {
            gak_format_fail("ELF hash table exceeds symbol limits"); return 0;
        }
        if (!gak_dependency_map(format, 0, hash_va,
                                (2u + buckets + chains) * 4u, &at)) return 0;
        *count = chains;
        return 1;
    }
    uint64_t first = gak_number(bytes, at + 4, 4, big);
    uint64_t bloom = gak_number(bytes, at + 8, 4, big);
    if (!buckets || !bloom || buckets > 100000 || bloom > 100000 ||
        first > 100000) {
        gak_format_fail("ELF GNU hash table exceeds symbol limits"); return 0;
    }
    uint64_t delta = 16u + bloom * (format->bits == 32 ? 4u : 8u);
    if (hash_va > UINT64_MAX - delta) {
        gak_format_fail("ELF GNU hash address overflow"); return 0;
    }
    uint64_t bucket_va = hash_va + delta;
    if (!gak_dependency_map(format, 0, bucket_va, buckets * 4u, &at)) return 0;
    uint64_t last = 0;
    for (uint64_t index = 0; index < buckets; index++) {
        uint64_t symbol = gak_number(bytes, at + index * 4u, 4, big);
        if (symbol && (symbol < first || symbol >= 100000)) {
            gak_format_fail("ELF GNU hash bucket refers outside dynamic symbols"); return 0;
        }
        if (symbol && symbol < last) {
            gak_format_fail("ELF GNU hash buckets are out of order"); return 0;
        }
        if (symbol > last) last = symbol;
    }
    if (!last) { *count = first; return 1; }
    delta = (buckets + last - first) * 4u;
    if (bucket_va > UINT64_MAX - delta) {
        gak_format_fail("ELF GNU hash address overflow"); return 0;
    }
    uint64_t chain_va = bucket_va + delta;
    for (uint64_t symbol = last; symbol < 100000; symbol++) {
        uint64_t step = (symbol - last) * 4u;
        if (chain_va > UINT64_MAX - step ||
            !gak_dependency_map(format, 0, chain_va + step, 4, &at)) return 0;
        if (gak_number(bytes, at, 4, big) & 1u) {
            if (!gak_dependency_map(format, 0, chain_va, step + 4, &at)) return 0;
            *count = symbol + 1;
            return 1;
        }
    }
    gak_format_fail("ELF GNU hash chain has no terminator within symbol limit");
    return 0;
}

static int gak_elf_symbol_table(const GakFormat *format, int static_table,
                                uint64_t *symbol_at,
                                uint64_t *symbol_count, uint64_t *string_at,
                                uint64_t *string_size) {
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    unsigned width = format->bits == 32 ? 4 : 8;
    uint64_t entry_size = width == 4 ? 16 : 24;
    int big = format->big_endian != 0;
    uint64_t dynsym = 0, found = 0;
    for (uint64_t index = 0; index < format->sections; index++) {
        uint64_t at = format->section_table + index * format->section_stride;
        if (gak_number(bytes, at + 4, 4, big) != (static_table ? 2u : 11u)) continue;
        if (found++) {
            gak_format_fail(static_table ? "multiple ELF static symbol sections" :
                                           "multiple ELF dynamic symbol sections"); return 0;
        }
        dynsym = at;
    }
    if (found) {
        uint64_t linked = gak_number(bytes, dynsym + (width == 4 ? 24 : 40), 4, big);
        uint64_t entry = gak_number(bytes, dynsym + (width == 4 ? 36 : 56), width, big);
        if (entry != entry_size) {
            gak_format_fail(static_table ? "invalid ELF static symbol entry size" :
                                           "invalid ELF dynamic symbol entry size"); return 0;
        }
        if (!linked || linked >= format->sections ||
            gak_number(bytes, format->section_table + linked * format->section_stride + 4,
                       4, big) != 3) {
            gak_format_fail(static_table ? "ELF static symbols need a linked SHT_STRTAB" :
                                           "ELF dynamic symbols need a linked SHT_STRTAB"); return 0;
        }
        uint64_t strings = format->section_table + linked * format->section_stride;
        uint64_t symbol_flags = gak_number(bytes, dynsym + 8, width, big);
        uint64_t string_flags = gak_number(bytes, strings + 8, width, big);
        if ((symbol_flags | string_flags) & 0x800u) {
            gak_format_fail(static_table ? "compressed ELF static symbol tables are unsupported" :
                                           "compressed ELF dynamic symbol tables are unsupported"); return 0;
        }
        uint64_t symbol_size = gak_number(bytes, dynsym + (width == 4 ? 20 : 32), width, big);
        if (symbol_size % entry_size) {
            gak_format_fail(static_table ? "ELF static symbol table has a partial entry" :
                                           "ELF dynamic symbol table has a partial entry"); return 0;
        }
        *symbol_at = gak_number(bytes, dynsym + (width == 4 ? 16 : 24), width, big);
        *symbol_count = symbol_size / entry_size;
        *string_at = gak_number(bytes, strings + (width == 4 ? 16 : 24), width, big);
        *string_size = gak_number(bytes, strings + (width == 4 ? 20 : 32), width, big);
        if (!gak_span(length, *symbol_at, symbol_size) ||
            !gak_span(length, *string_at, *string_size)) {
            gak_format_fail(static_table ? "ELF static symbol table outside captured Source" :
                                           "ELF dynamic symbol table outside captured Source"); return 0;
        }
        return 1;
    }
    if (static_table) { *symbol_count = 0; return 1; }
    uint64_t dynamic_at = 0, dynamic_size = 0;
    int dynamic_seen = 0;
    for (uint64_t index = 0; index < format->program_count; index++) {
        uint64_t at = format->program_table + index * format->program_stride;
        if (gak_number(bytes, at, 4, big) != 2) continue;
        dynamic_seen = 1;
        dynamic_at = gak_number(bytes, at + (width == 4 ? 4 : 8), width, big);
        dynamic_size = gak_number(bytes, at + (width == 4 ? 16 : 32), width, big);
        break;
    }
    if (!dynamic_seen) { *symbol_count = 0; return 1; }
    if (!dynamic_size || dynamic_size > 1024u * 1024u ||
        dynamic_size % (2u * width)) {
        gak_format_fail("invalid ELF dynamic table size"); return 0;
    }
    if (!gak_span(length, dynamic_at, dynamic_size)) {
        gak_format_fail("ELF dynamic table outside captured Source"); return 0;
    }
    static const uint64_t tags[] = {4, 5, 6, 10, 11, 0x6ffffef5u};
    uint64_t values[6] = {0};
    int seen[6] = {0};
    int terminated = 0;
    for (uint64_t index = 0; index < dynamic_size / (2u * width); index++) {
        uint64_t at = dynamic_at + index * (2u * width);
        uint64_t tag = gak_number(bytes, at, width, big);
        if (!tag) { terminated = 1; break; }
        for (size_t field = 0; field < 6; field++) {
            if (tag != tags[field]) continue;
            if (seen[field]) {
                gak_format_fail("duplicate ELF dynamic symbol tag"); return 0;
            }
            seen[field] = 1;
            values[field] = gak_number(bytes, at + width, width, big);
            break;
        }
    }
    if (!terminated) {
        gak_format_fail("ELF dynamic table has no DT_NULL terminator"); return 0;
    }
    if (!seen[2]) { *symbol_count = 0; return 1; }
    if (!seen[4] || values[4] != entry_size) {
        gak_format_fail("invalid ELF DT_SYMENT"); return 0;
    }
    if (!seen[1]) {
        gak_format_fail("ELF dynamic symbols lack DT_STRTAB"); return 0;
    }
    if (!seen[3]) {
        gak_format_fail("ELF dynamic symbols lack DT_STRSZ"); return 0;
    }
    if (!seen[0] && !seen[5]) {
        gak_format_fail("ELF dynamic symbol count needs DT_HASH or DT_GNU_HASH"); return 0;
    }
    if (values[3] > 16u * 1024u * 1024u) {
        gak_format_fail("ELF dynamic string table exceeds 16 MiB"); return 0;
    }
    if (!gak_elf_symbol_hash_count(format, seen[0] ? values[0] : values[5],
                                   !seen[0], symbol_count)) return 0;
    *string_size = values[3];
    *symbol_at = 0;
    *string_at = 0;
    if (*symbol_count &&
        !gak_dependency_map(format, 0, values[2], *symbol_count * entry_size,
                            symbol_at)) return 0;
    if (*string_size &&
        !gak_dependency_map(format, 0, values[1], *string_size,
                            string_at)) return 0;
    return 1;
}

static int gak_elf_symbol_scan(const GakFormat *format, int static_table,
                               int64_t selected,
                               GakSymbolSelection *result) {
    if (format->kind != 2) {
        gak_format_fail(static_table ? "ELF static symbols require an ELF image" :
                                       "ELF dynamic symbols require an ELF image"); return 0;
    }
    const GakSourceHead *source = format->source;
    const uint8_t *bytes = source->backing + 8 + source->start;
    uint64_t length = source->end - source->start;
    uint64_t symbols = 0, count = 0, strings = 0, string_size = 0;
    if (!gak_elf_symbol_table(format, static_table, &symbols, &count,
                              &strings, &string_size)) return 0;
    if (count > 100000) {
        gak_format_fail(static_table ? "ELF static symbols exceed 100000" :
                                       "ELF dynamic symbols exceed 100000"); return 0;
    }
    if (string_size > 16u * 1024u * 1024u) {
        gak_format_fail("ELF dynamic string table exceeds 16 MiB"); return 0;
    }
    uint64_t entry_size = format->bits == 32 ? 16 : 24;
    if (!gak_span(length, symbols, count * entry_size) ||
        !gak_span(length, strings, string_size)) {
        gak_format_fail(static_table ? "ELF static symbol table outside captured Source" :
                                       "ELF dynamic symbol table outside captured Source"); return 0;
    }
    result->count = count;
    uint64_t total_name_bytes = 0;
    int big = format->big_endian != 0;
    for (uint64_t index = 0; index < count; index++) {
        uint64_t at = symbols + index * entry_size;
        uint64_t name_offset = gak_number(bytes, at, 4, big);
        const uint8_t *name = NULL;
        size_t name_length = 0;
        if (name_offset) {
            if (name_offset >= string_size) {
                gak_format_fail(static_table ? "ELF static symbol name offset out of range" :
                                               "ELF dynamic symbol name offset out of range"); return 0;
            }
            uint64_t available = string_size - name_offset;
            if (available > 4097) available = 4097;
            while (name_length < available &&
                   bytes[strings + name_offset + name_length]) name_length++;
            if (name_length == available) {
                gak_format_fail(static_table ? "unterminated or oversized ELF static symbol name" :
                                               "unterminated or oversized ELF dynamic symbol name"); return 0;
            }
            if (!name_length || name_length > 4096) {
                gak_format_fail(static_table ? "empty or oversized ELF static symbol name" :
                                               "empty or oversized ELF dynamic symbol name"); return 0;
            }
            if (total_name_bytes > 16u * 1024u * 1024u - name_length) {
                gak_format_fail(static_table ? "ELF static symbol names exceed 16 MiB" :
                                               "ELF dynamic symbol names exceed 16 MiB"); return 0;
            }
            total_name_bytes += name_length;
            name = bytes + strings + name_offset;
        }
        if (selected < 0 || (uint64_t)selected != index) continue;
        uint64_t info_at = at + (entry_size == 16 ? 12 : 4);
        uint8_t info = bytes[info_at];
        result->name = name;
        result->name_length = name_length;
        result->binding = info >> 4;
        result->kind = info & 15u;
        result->visibility = bytes[info_at + 1] & 3u;
        result->section = (uint16_t)gak_number(bytes, info_at + 2, 2, big);
        result->address = gak_number(bytes, at + (entry_size == 16 ? 4 : 8),
                                     entry_size == 16 ? 4 : 8, big);
        result->size = gak_number(bytes, at + (entry_size == 16 ? 8 : 16),
                                  entry_size == 16 ? 4 : 8, big);
    }
    return 1;
}

int64_t gak_native_formats_symbol_count(const void *value, int static_table) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    GakSymbolSelection result = {0};
    if (!gak_elf_symbol_scan(value, static_table, -1, &result)) return -1;
    return (int64_t)result.count;
}

int64_t gak_native_formats_symbol_number(const void *value, int64_t index,
                                          int part, int static_table) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return -1; }
    if (index < 0) {
        gak_format_fail(static_table ? "static symbol index out of range" :
                                       "dynamic symbol index out of range"); return -1;
    }
    GakSymbolSelection result = {0};
    if (!gak_elf_symbol_scan(value, static_table, index, &result)) return -1;
    if ((uint64_t)index >= result.count) {
        gak_format_fail(static_table ? "static symbol index out of range" :
                                       "dynamic symbol index out of range"); return -1;
    }
    if (part == 0) {
        if (result.size > INT64_MAX) {
            gak_format_fail(static_table ? "static symbol size outside i64 range" :
                                           "dynamic symbol size outside i64 range"); return -1;
        }
        return (int64_t)result.size;
    }
    if (part == 1) return result.section;
    return result.section != 0;
}

static const char *gak_elf_symbol_binding(uint8_t value) {
    switch (value) {
        case 0: return "local";
        case 1: return "global";
        case 2: return "weak";
        case 10: return "gnu_unique";
        default: return "unknown";
    }
}

static const char *gak_elf_symbol_kind(uint8_t value) {
    switch (value) {
        case 0: return "notype";
        case 1: return "object";
        case 2: return "function";
        case 3: return "section";
        case 4: return "file";
        case 5: return "common";
        case 6: return "tls";
        case 10: return "gnu_ifunc";
        default: return "unknown";
    }
}

static const char *gak_elf_symbol_visibility(uint8_t value) {
    switch (value) {
        case 0: return "default";
        case 1: return "internal";
        case 2: return "hidden";
        default: return "protected";
    }
}

static const char *gak_elf_symbol_role(const GakSymbolSelection *symbol) {
    if (!symbol->section) return "undefined";
    if ((symbol->binding == 1 || symbol->binding == 2 || symbol->binding == 10) &&
        (symbol->visibility == 0 || symbol->visibility == 3)) return "exported";
    return "local";
}

void *gak_native_formats_symbol_text(const void *value, int64_t index,
                                      int part, int static_table) {
    gak_formats_error = NULL;
    if (!value) { gak_format_fail("invalid Format"); return NULL; }
    if (index < 0) {
        gak_format_fail(static_table ? "static symbol index out of range" :
                                       "dynamic symbol index out of range"); return NULL;
    }
    GakSymbolSelection result = {0};
    if (!gak_elf_symbol_scan(value, static_table, index, &result)) return NULL;
    if ((uint64_t)index >= result.count) {
        gak_format_fail(static_table ? "static symbol index out of range" :
                                       "dynamic symbol index out of range"); return NULL;
    }
    if (part == 0) return gak_dependency_text(result.name, result.name_length);
    if (part == 5) {
        char address[19];
        int length = snprintf(address, sizeof(address), "0x%llx",
                              (unsigned long long)result.address);
        return length < 0 || (size_t)length >= sizeof(address) ? NULL
            : gak_format_box(address, (size_t)length);
    }
    if (part == 6) {
        void *name = result.name_length
            ? gak_dependency_text(result.name, result.name_length) : NULL;
        if (result.name_length && !name) return NULL;
        uint64_t name_size = 0;
        if (name) memcpy(&name_size, name, 8);
        const char *name_text = name ? (const char *)name + 8 : "(unnamed)";
        if (!name) name_size = 9;
        char summary[16512];
        int length = snprintf(summary, sizeof(summary), "%.*s [%s %s] @ 0x%llx",
                              (int)name_size, name_text, gak_elf_symbol_role(&result),
                              gak_elf_symbol_kind(result.kind),
                              (unsigned long long)result.address);
        if (name) gak_dependency_text_free(name);
        if (length < 0 || (size_t)length >= sizeof(summary)) {
            gak_format_fail("invalid dynamic symbol summary"); return NULL;
        }
        return gak_format_box(summary, (size_t)length);
    }
    const char *text = part == 1 ? gak_elf_symbol_binding(result.binding)
        : part == 2 ? gak_elf_symbol_kind(result.kind)
        : part == 3 ? gak_elf_symbol_visibility(result.visibility)
        : gak_elf_symbol_role(&result);
    return gak_format_box(text, strlen(text));
}

static const void *gak_format_status(int present) {
    return present ? (const void *)&text_present : (const void *)&text_absent;
}

static const void *gak_bind_now_status(const GakFormat *format) {
    if (format->bind_now == 0) return &text_unknown;
    return gak_format_status(format->bind_now == 2);
}

const void *gak_native_formats_signal(const void *value, const void *name) {
    const GakFormat *format = value;
    gak_formats_error = NULL;
    if (!format || !name) { gak_format_fail("invalid format signal"); return NULL; }
    if (gak_format_name(name, "pe.high_entropy_va") ||
        gak_format_name(name, "pe.dynamic_base") ||
        gak_format_name(name, "pe.nx_compat") ||
        gak_format_name(name, "pe.guard_cf")) {
        if (format->kind != 1 ||
            (format->bits == 32 && gak_format_name(name, "pe.high_entropy_va")))
            return &text_not_applicable;
        if (!format->dll_available) return &text_unknown;
        uint64_t mask = gak_format_name(name, "pe.high_entropy_va") ? 0x0020u :
                        gak_format_name(name, "pe.dynamic_base") ? 0x0040u :
                        gak_format_name(name, "pe.nx_compat") ? 0x0100u : 0x4000u;
        return gak_format_status((format->dll_characteristics & mask) != 0);
    }
    if (gak_format_name(name, "pe.section_wx")) {
        return format->kind == 1 ? gak_format_status(format->section_wx != 0) :
                                   (const void *)&text_not_applicable;
    }
    if (gak_format_name(name, "elf.et_dyn")) {
        if (format->kind == 1) return &text_not_applicable;
        if (format->file_type == 3) return &text_present;
        if (format->file_type == 2) return &text_absent;
        return &text_unknown;
    }
    if (gak_format_name(name, "elf.gnu_stack_nx")) {
        if (format->kind == 1) return &text_not_applicable;
        if (!format->stack_available) return &text_unknown;
        return gak_format_status((format->stack_flags & 1u) == 0);
    }
    if (gak_format_name(name, "elf.gnu_relro")) {
        if (format->kind == 1) return &text_not_applicable;
        if (!format->program_headers_present) return &text_unknown;
        return gak_format_status(format->relro_segment != 0);
    }
    if (gak_format_name(name, "elf.bind_now")) {
        return format->kind == 1 ? (const void *)&text_not_applicable :
                                   gak_bind_now_status(format);
    }
    if (gak_format_name(name, "elf.relro_now")) {
        if (format->kind == 1) return &text_not_applicable;
        if (!format->program_headers_present) return &text_unknown;
        if (!format->relro_segment) return &text_absent;
        return gak_bind_now_status(format);
    }
    if (gak_format_name(name, "elf.load_rwx")) {
        if (format->kind == 1) return &text_not_applicable;
        if (!format->program_headers_present || !format->load_count) return &text_unknown;
        return gak_format_status(format->load_rwx != 0);
    }
    gak_format_fail("unknown format signal");
    return NULL;
}
