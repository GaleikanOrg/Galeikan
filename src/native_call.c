/* Bounded one-shot transport for calling compiled Galeikan functions.
 * This helper is linked only when the compiler emits native call dispatch.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <wchar.h>
#define gak_read _read
#define gak_write _write
#define gak_dup _dup
#define gak_dup2 _dup2
#define gak_close _close
#else
#include <unistd.h>
#define gak_read read
#define gak_write write
#define gak_dup dup
#define gak_dup2 dup2
#define gak_close close
#endif

#define GAK_CALL_MAX_REQUEST (1024u * 1024u)
#define GAK_CALL_MAX_PAYLOAD 500000u
#define GAK_CALL_MAX_ARGS 64u
#define GAK_CALL_MAX_LIST 100000u
#define GAK_CALL_MEMORY_LIMIT 67108864u

extern uint64_t gak_argc;
extern void *gak_argv;
extern uint64_t gak_list_bytes;
extern uint64_t gak_str_bytes;
extern uint64_t gak_bytes_allocated;

/* The generated entry point sets this after gak_native_init processes grants. */
int gak_native_call_grants_processed = 0;

typedef struct {
    uint8_t tag;
    uint32_t length;
    uint64_t scalar;
    uint8_t *box;
    uint64_t list_bytes;
    uint64_t element_bytes;
} GakCallArgument;

typedef struct GakCallSource {
    const uint8_t *backing;
    const struct GakCallSource *parent;
    uint64_t start, end, depth;
    const uint8_t *sha256;
    uint64_t operation, range_start, range_end, inserted_size;
    const uint8_t *label, *origin;
    uint64_t address_kind, address;
} GakCallSource;

typedef struct {
    const GakCallSource *source;
    uint64_t offset, width;
    const uint8_t *decoder;
    uint64_t value;
} GakCallObservation;

typedef struct {
    size_t length;
    int failed;
} GakCallJson;

extern const uint8_t *gak_native_call_hash(const uint8_t *bytes, uint64_t length);

static uint8_t gak_call_request[GAK_CALL_MAX_REQUEST + 1u];
static uint8_t gak_call_response_payload[GAK_CALL_MAX_PAYLOAD];
static GakCallArgument gak_call_arguments[GAK_CALL_MAX_ARGS];
static char gak_call_name[256];
static uint8_t gak_call_arg_count;
static uint64_t gak_call_read_mask;
static int gak_call_active;
static int gak_call_result_written;
static int gak_call_protocol_fd = -1;
int gak_native_call_serve_mode;
static uint64_t gak_call_session_bytes;
static uint32_t gak_call_session_calls;
static uint64_t gak_call_transport_bytes;

void gak_native_call_error(const uint8_t *message, uint64_t length);

static void gak_call_fail(const char *message) {
    fprintf(stderr, "Galeikan call: %s\n", message);
    fflush(stderr);
    exit(EXIT_FAILURE);
}

static uint16_t gak_call_u16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t gak_call_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t gak_call_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (unsigned index = 0; index < 8; index++)
        value |= (uint64_t)bytes[index] << (8u * index);
    return value;
}

static void gak_call_put_u32(uint8_t *bytes, uint32_t value) {
    for (unsigned index = 0; index < 4; index++)
        bytes[index] = (uint8_t)(value >> (8u * index));
}

static void gak_call_put_u64(uint8_t *bytes, uint64_t value) {
    for (unsigned index = 0; index < 8; index++)
        bytes[index] = (uint8_t)(value >> (8u * index));
}

static int gak_call_utf8(const uint8_t *bytes, size_t length);

static void gak_call_account_transport(uint64_t amount) {
    if (amount > GAK_CALL_MEMORY_LIMIT - gak_call_transport_bytes)
        gak_call_fail("native call transport memory exceeds 64 MiB");
    gak_call_transport_bytes += amount;
}

static uint8_t *gak_call_box(const uint8_t *payload, uint32_t length) {
    gak_call_account_transport((uint64_t)length + 9u);
    uint8_t *box = malloc((size_t)length + 9u);
    if (!box) gak_call_fail("native allocation failed");
    uint64_t boxed_length = length;
    memcpy(box, &boxed_length, 8);
    memcpy(box + 8, payload, length);
    box[8u + length] = 0;
    return box;
}

static void gak_call_parse_list(GakCallArgument *argument, const uint8_t *payload) {
    if (argument->length < 4 || argument->length > GAK_CALL_MAX_PAYLOAD)
        gak_call_fail("invalid list payload length");
    uint32_t count = gak_call_u32(payload);
    if (count > GAK_CALL_MAX_LIST || (argument->tag == 11 && count != 0))
        gak_call_fail("invalid list item count");
    gak_call_account_transport(((uint64_t)count + 1u) * sizeof(uint64_t));
    uint64_t *list = calloc((size_t)count + 1u, sizeof(*list));
    if (!list) gak_call_fail("native allocation failed");
    list[0] = count;
    argument->box = (uint8_t *)list;
    argument->list_bytes = ((uint64_t)count + 1u) * 8u;
    size_t offset = 4;
    for (uint32_t index = 0; index < count; index++) {
        if (argument->tag == 6 || argument->tag == 7) {
            if (argument->length - offset < 8) gak_call_fail("truncated list integer");
            list[index + 1u] = gak_call_u64(payload + offset);
            offset += 8;
        } else if (argument->tag == 8) {
            if (argument->length - offset < 1 || payload[offset] > 1)
                gak_call_fail("invalid list boolean");
            list[index + 1u] = payload[offset++];
        } else if (argument->tag == 9 || argument->tag == 10) {
            if (argument->length - offset < 4) gak_call_fail("truncated list item length");
            uint32_t item_length = gak_call_u32(payload + offset);
            offset += 4;
            if (item_length > GAK_CALL_MAX_PAYLOAD || item_length > argument->length - offset)
                gak_call_fail("invalid list item length");
            if (argument->tag == 9 && !gak_call_utf8(payload + offset, item_length))
                gak_call_fail("list string is not valid UTF-8");
            list[index + 1u] = (uint64_t)(uintptr_t)gak_call_box(payload + offset, item_length);
            argument->element_bytes += (uint64_t)item_length + 8u;
            offset += item_length;
        }
    }
    if (offset != argument->length) gak_call_fail("trailing list data");
}

static int gak_call_utf8(const uint8_t *bytes, size_t length) {
    size_t index = 0;
    while (index < length) {
        uint32_t codepoint;
        uint32_t minimum;
        unsigned continuation;
        uint8_t first = bytes[index++];
        if (first < 0x80) continue;
        if (first >= 0xc2 && first <= 0xdf) {
            codepoint = first & 0x1fu;
            minimum = 0x80u;
            continuation = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            codepoint = first & 0x0fu;
            minimum = 0x800u;
            continuation = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = first & 0x07u;
            minimum = 0x10000u;
            continuation = 3;
        } else {
            return 0;
        }
        if (continuation > length - index) return 0;
        for (unsigned part = 0; part < continuation; part++) {
            uint8_t next = bytes[index++];
            if ((next & 0xc0u) != 0x80u) return 0;
            codepoint = (codepoint << 6) | (next & 0x3fu);
        }
        if (codepoint < minimum || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return 0;
    }
    return 1;
}

static void gak_call_write_all(const uint8_t *bytes, size_t length) {
    while (length) {
        int written = (int)gak_write(gak_call_protocol_fd, bytes, (unsigned)length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) gak_call_fail("cannot write protocol response");
        bytes += (size_t)written;
        length -= (size_t)written;
    }
}

static void gak_call_parse_request(size_t length) {
    gak_call_arg_count = 0;
    gak_call_read_mask = 0;
    memset(gak_call_arguments, 0, sizeof(gak_call_arguments));
    if (length < 11 || memcmp(gak_call_request, "GAKCALL1", 8) != 0)
        gak_call_fail("invalid request magic");

    size_t offset = 8;
    uint16_t name_length = gak_call_u16(gak_call_request + offset);
    offset += 2;
    if (!name_length || name_length > 255 || (size_t)name_length + 1 > length - offset)
        gak_call_fail("invalid function name length");
    if (memchr(gak_call_request + offset, 0, name_length) ||
        !gak_call_utf8(gak_call_request + offset, name_length))
        gak_call_fail("function name must be valid UTF-8 without NUL");
    memcpy(gak_call_name, gak_call_request + offset, name_length);
    gak_call_name[name_length] = 0;
    offset += name_length;

    gak_call_arg_count = gak_call_request[offset++];
    if (gak_call_arg_count > GAK_CALL_MAX_ARGS)
        gak_call_fail("too many arguments");
    for (unsigned index = 0; index < gak_call_arg_count; index++) {
        if (length - offset < 5) gak_call_fail("truncated argument header");
        GakCallArgument *argument = &gak_call_arguments[index];
        argument->tag = gak_call_request[offset++];
        argument->length = gak_call_u32(gak_call_request + offset);
        offset += 4;
        if (argument->length > length - offset) gak_call_fail("truncated argument payload");
        const uint8_t *payload = gak_call_request + offset;
        switch (argument->tag) {
        case 1: /* i64 */
        case 2: /* u64 */
            if (argument->length != 8) gak_call_fail("invalid integer payload length");
            argument->scalar = gak_call_u64(payload);
            break;
        case 3: /* bool */
            if (argument->length != 1 || payload[0] > 1)
                gak_call_fail("invalid boolean payload");
            argument->scalar = payload[0];
            break;
        case 4: /* str */
        case 5: /* bytes */
            if (argument->length > GAK_CALL_MAX_PAYLOAD)
                gak_call_fail("argument exceeds 500000 bytes");
            if (argument->tag == 4 && !gak_call_utf8(payload, argument->length))
                gak_call_fail("string argument is not valid UTF-8");
            argument->box = gak_call_box(payload, argument->length);
            argument->element_bytes = (uint64_t)argument->length + 8u;
            break;
        case 6: /* List<i64> */
        case 7: /* List<u64> */
        case 8: /* List<bool> */
        case 9: /* List<str> */
        case 10: /* List<bytes> */
        case 11: /* untyped empty list */
            gak_call_parse_list(argument, payload);
            break;
        default:
            gak_call_fail("invalid argument tag");
        }
        offset += argument->length;
    }
    if (offset != length) gak_call_fail("trailing request data");
}

static void gak_call_read_request(void) {
    size_t length = 0;
    for (;;) {
        int received = (int)gak_read(0, gak_call_request + length,
            (unsigned)(GAK_CALL_MAX_REQUEST + 1u - length));
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) gak_call_fail("cannot read protocol request");
        if (received == 0) break;
        length += (size_t)received;
        if (length > GAK_CALL_MAX_REQUEST) gak_call_fail("request exceeds 1 MiB");
    }
    gak_call_parse_request(length);
}

static int gak_call_read_frame(void) {
    uint8_t header[4];
    size_t offset = 0;
    while (offset < sizeof(header)) {
        int received = (int)gak_read(0, header + offset, (unsigned)(sizeof(header) - offset));
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) gak_call_fail("cannot read session frame");
        if (received == 0) {
            if (offset != 0) gak_call_fail("truncated session frame");
            return 0;
        }
        offset += (size_t)received;
    }
    if (gak_call_session_calls >= 10000u)
        gak_call_fail("session exceeds 10000 calls");
    uint32_t length = gak_call_u32(header);
    if (length > GAK_CALL_MAX_REQUEST) gak_call_fail("request exceeds 1 MiB");
    if (gak_call_session_bytes > GAK_CALL_MEMORY_LIMIT - length)
        gak_call_fail("session requests exceed 64 MiB");
    gak_call_session_bytes += length;
    gak_call_session_calls++;
    offset = 0;
    while (offset < length) {
        int received = (int)gak_read(0, gak_call_request + offset, (unsigned)(length - offset));
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) gak_call_fail("truncated session request");
        offset += (size_t)received;
    }
    gak_call_parse_request(length);
    return 1;
}

#ifndef _WIN32
static int gak_call_is_grant(const char *option) {
    return strcmp(option, "--allow-read") == 0 ||
        strcmp(option, "--allow-connect") == 0 ||
        strcmp(option, "--allow-process") == 0 ||
        strcmp(option, "--allow-python") == 0;
}
#endif

#ifdef _WIN32
static int gak_call_is_grant_wide(const wchar_t *option) {
    return wcscmp(option, L"--allow-read") == 0 ||
        wcscmp(option, L"--allow-connect") == 0 ||
        wcscmp(option, L"--allow-process") == 0 ||
        wcscmp(option, L"--allow-python") == 0;
}
#endif

int gak_native_call_begin(void) {
    if (gak_call_active) gak_call_fail("call mode initialized twice");
    if (gak_argc < 2 || !gak_argv) return 0;
#ifdef _WIN32
    wchar_t **arguments = (wchar_t **)gak_argv;
    if (wcscmp(arguments[1], L"--galeikan-call") == 0) gak_native_call_serve_mode = 0;
    else if (wcscmp(arguments[1], L"--galeikan-serve") == 0) gak_native_call_serve_mode = 1;
    else return 0;
#else
    char **arguments = (char **)gak_argv;
    if (strcmp(arguments[1], "--galeikan-call") == 0) gak_native_call_serve_mode = 0;
    else if (strcmp(arguments[1], "--galeikan-serve") == 0) gak_native_call_serve_mode = 1;
    else return 0;
#endif
    gak_call_active = 1;

    /* Keep the executable name at argv[0] for std.cli's normal indexing. */
    size_t count = (size_t)gak_argc;
#ifdef _WIN32
    wchar_t **filtered = calloc(count, sizeof(*filtered));
#else
    char **filtered = calloc(count, sizeof(*filtered));
#endif
    if (!filtered) gak_call_fail("native allocation failed");
    size_t kept = 0;
    filtered[kept++] = arguments[0];
    int options = 1;
    for (size_t index = 2; index < count; index++) {
#ifdef _WIN32
        if (options && wcscmp(arguments[index], L"--") == 0) {
#else
        if (options && strcmp(arguments[index], "--") == 0) {
#endif
            options = 0;
            continue;
        }
        if (options && !gak_native_call_grants_processed) {
#ifdef _WIN32
            int grant = gak_call_is_grant_wide(arguments[index]);
#else
            int grant = gak_call_is_grant(arguments[index]);
#endif
            if (grant) {
                if (++index >= count) gak_call_fail("grant option needs a value");
                continue;
            }
        }
        filtered[kept++] = arguments[index];
    }
    gak_argc = (uint64_t)kept;
    gak_argv = filtered;

    if (fflush(stdout) != 0) gak_call_fail("cannot flush stdout");
    gak_call_protocol_fd = gak_dup(1);
    if (gak_call_protocol_fd < 0 || gak_dup2(2, 1) < 0)
        gak_call_fail("cannot reserve stdout for protocol");
#ifdef _WIN32
    if (_setmode(0, _O_BINARY) < 0 || _setmode(gak_call_protocol_fd, _O_BINARY) < 0)
        gak_call_fail("cannot set binary protocol mode");
#endif
    if (gak_native_call_serve_mode) {
        gak_call_write_all((const uint8_t *)"GAKRDY01", 8);
        if (!gak_call_read_frame()) exit(EXIT_SUCCESS);
    } else {
        gak_call_read_request();
    }
    return 1;
}

int gak_native_call_next(void) {
    if (!gak_call_active || !gak_call_result_written)
        gak_call_fail("session response is not available");
    if (!gak_native_call_serve_mode) return 0;
    gak_call_result_written = 0;
    return gak_call_read_frame();
}

const char *gak_native_call_function(void) {
    if (!gak_call_active) gak_call_fail("call mode is not active");
    return gak_call_name;
}

static void gak_call_argument_error(const char *message) {
    if (!gak_native_call_serve_mode) gak_call_fail(message);
    gak_native_call_error((const uint8_t *)message, strlen(message));
}

int gak_native_call_error_pending(void) {
    return gak_call_result_written;
}

void gak_native_call_expect_arity(uint64_t expected_count) {
    if (!gak_call_active) gak_call_fail("call mode is not active");
    if (expected_count != gak_call_arg_count)
        gak_call_argument_error("function argument count mismatch");
}

static void gak_call_reserve(uint64_t *counter, uint64_t amount) {
    if (*counter > GAK_CALL_MEMORY_LIMIT || amount > GAK_CALL_MEMORY_LIMIT - *counter)
        gak_call_fail("native call argument exceeds allocation limit");
    *counter += amount;
}

uint64_t gak_native_call_arg(uint64_t index, uint64_t expected_tag) {
    if (!gak_call_active) gak_call_fail("call mode is not active");
    if (index >= gak_call_arg_count) {
        gak_call_argument_error("function argument count mismatch");
        return 0;
    }
    GakCallArgument *argument = &gak_call_arguments[index];
    if (argument->tag != expected_tag &&
        !(argument->tag == 11 && expected_tag >= 6 && expected_tag <= 10))
    {
        gak_call_argument_error("function argument type mismatch");
        return 0;
    }
    uint64_t bit = UINT64_C(1) << (unsigned)index;
    if (gak_call_read_mask & bit) {
        gak_call_argument_error("function argument read twice");
        return 0;
    }
    if (expected_tag >= 6 && expected_tag <= 10)
        gak_call_reserve(&gak_list_bytes, argument->list_bytes);
    if (expected_tag == 4 || expected_tag == 9)
        gak_call_reserve(&gak_str_bytes, argument->element_bytes);
    if (expected_tag == 5 || expected_tag == 10)
        gak_call_reserve(&gak_bytes_allocated, argument->element_bytes);
    gak_call_read_mask |= bit;
    if (expected_tag >= 4 && expected_tag <= 10)
        return (uint64_t)(uintptr_t)argument->box;
    return argument->scalar;
}

static void gak_call_result_error(const char *message) {
    if (!gak_native_call_serve_mode) gak_call_fail(message);
    gak_native_call_error((const uint8_t *)message, strlen(message));
}

static uint32_t gak_call_encode_list(uint8_t tag, uint64_t value) {
    if (!value) {
        gak_call_result_error("null list result");
        return 0;
    }
    const uint64_t *list = (const uint64_t *)(uintptr_t)value;
    uint64_t count = list[0];
    if (count > GAK_CALL_MAX_LIST) {
        gak_call_result_error("result list exceeds 100000 items");
        return 0;
    }
    size_t offset = 4;
    gak_call_put_u32(gak_call_response_payload, (uint32_t)count);
    for (uint64_t index = 0; index < count; index++) {
        uint64_t item = list[index + 1u];
        if (tag == 6 || tag == 7) {
            if (GAK_CALL_MAX_PAYLOAD - offset < 8) {
                gak_call_result_error("result exceeds 500000 bytes");
                return 0;
            }
            gak_call_put_u64(gak_call_response_payload + offset, item);
            offset += 8;
        } else if (tag == 8) {
            if (item > 1) {
                gak_call_result_error("invalid list boolean result");
                return 0;
            }
            if (GAK_CALL_MAX_PAYLOAD - offset < 1) {
                gak_call_result_error("result exceeds 500000 bytes");
                return 0;
            }
            gak_call_response_payload[offset++] = (uint8_t)item;
        } else {
            if (!item) {
                gak_call_result_error("null boxed list item");
                return 0;
            }
            const uint8_t *box = (const uint8_t *)(uintptr_t)item;
            uint64_t item_length;
            memcpy(&item_length, box, 8);
            if (GAK_CALL_MAX_PAYLOAD - offset < 4u ||
                item_length > GAK_CALL_MAX_PAYLOAD - offset - 4u) {
                gak_call_result_error("result exceeds 500000 bytes");
                return 0;
            }
            if (tag == 9 && !gak_call_utf8(box + 8, (size_t)item_length)) {
                gak_call_result_error("list string result is not valid UTF-8");
                return 0;
            }
            gak_call_put_u32(gak_call_response_payload + offset, (uint32_t)item_length);
            offset += 4;
            memcpy(gak_call_response_payload + offset, box + 8, (size_t)item_length);
            offset += (size_t)item_length;
        }
    }
    return (uint32_t)offset;
}

static void gak_json_bytes(GakCallJson *json, const char *bytes, size_t length) {
    if (json->failed || length > GAK_CALL_MAX_PAYLOAD - json->length) {
        json->failed = 1;
        return;
    }
    memcpy(gak_call_response_payload + json->length, bytes, length);
    json->length += length;
}

static void gak_json_text(GakCallJson *json, const char *text) {
    gak_json_bytes(json, text, strlen(text));
}

static void gak_json_number(GakCallJson *json, uint64_t number) {
    char digits[32];
    int length = snprintf(digits, sizeof(digits), "%llu", (unsigned long long)number);
    if (length < 0 || (size_t)length >= sizeof(digits)) json->failed = 1;
    else gak_json_bytes(json, digits, (size_t)length);
}

static void gak_json_hex(GakCallJson *json, uint64_t number) {
    char digits[32];
    int length = snprintf(digits, sizeof(digits), "%llx", (unsigned long long)number);
    if (length < 0 || (size_t)length >= sizeof(digits)) json->failed = 1;
    else gak_json_bytes(json, digits, (size_t)length);
}

static void gak_json_escaped_content(GakCallJson *json, const uint8_t *bytes, size_t length) {
    static const char hex[] = "0123456789abcdef";
    if (!bytes || length > GAK_CALL_MAX_PAYLOAD || !gak_call_utf8(bytes, length)) {
        json->failed = 1;
        return;
    }
    for (size_t index = 0; index < length && !json->failed; index++) {
        uint8_t byte = bytes[index];
        if (byte == '"' || byte == '\\') {
            char escaped[2] = {'\\', (char)byte};
            gak_json_bytes(json, escaped, 2);
        } else if (byte < 0x20) {
            char escaped[6] = {'\\', 'u', '0', '0', hex[byte >> 4], hex[byte & 15]};
            gak_json_bytes(json, escaped, 6);
        } else {
            gak_json_bytes(json, (const char *)&bytes[index], 1);
        }
    }
}

static void gak_json_box_content(GakCallJson *json, const uint8_t *box) {
    uint64_t length;
    if (!box) { json->failed = 1; return; }
    memcpy(&length, box, 8);
    if (length > GAK_CALL_MAX_PAYLOAD) { json->failed = 1; return; }
    gak_json_escaped_content(json, box + 8, (size_t)length);
}

static void gak_json_box(GakCallJson *json, const uint8_t *box) {
    gak_json_text(json, "\"");
    gak_json_box_content(json, box);
    gak_json_text(json, "\"");
}

/* Native file/process metadata is escaped for console rendering. Decode it
 * before JSON encoding so Python receives the original path or label. */
static void gak_json_metadata_content(GakCallJson *json, const uint8_t *box) {
    uint64_t length;
    if (!box) { json->failed = 1; return; }
    memcpy(&length, box, 8);
    if (length > GAK_CALL_MAX_PAYLOAD) { json->failed = 1; return; }
    uint8_t *raw = malloc((size_t)length + 1u);
    if (!raw) { json->failed = 1; return; }
    size_t used = 0;
    for (size_t index = 0; index < (size_t)length && !json->failed; index++) {
        uint8_t byte = box[8u + index];
        if (byte != '\\') { raw[used++] = byte; continue; }
        if (++index >= (size_t)length) { json->failed = 1; break; }
        byte = box[8u + index];
        if (byte == '\\' || byte == '"') raw[used++] = byte;
        else if (byte == 'n') raw[used++] = '\n';
        else if (byte == 'r') raw[used++] = '\r';
        else if (byte == 't') raw[used++] = '\t';
        else if (byte == '0') raw[used++] = 0;
        else if (byte == 'u' && index + 2u < (size_t)length &&
                 box[9u + index] == '{') {
            index += 2;
            unsigned decoded = 0, digits = 0;
            while (index < (size_t)length && box[8u + index] != '}' && digits < 2) {
                byte = box[8u + index];
                unsigned nibble = byte >= '0' && byte <= '9' ? (unsigned)(byte - '0') :
                    byte >= 'a' && byte <= 'f' ? (unsigned)(byte - 'a') + 10u : 256u;
                if (nibble > 15u) { json->failed = 1; break; }
                decoded = decoded * 16u + nibble;
                digits++;
                index++;
            }
            if (json->failed || !digits || index >= (size_t)length ||
                box[8u + index] != '}' || decoded > 127u) {
                json->failed = 1; break;
            }
            raw[used++] = (uint8_t)decoded;
        } else { json->failed = 1; break; }
    }
    if (!json->failed) gak_json_escaped_content(json, raw, used);
    free(raw);
}

static void gak_json_metadata_box(GakCallJson *json, const uint8_t *box) {
    gak_json_text(json, "\"");
    gak_json_metadata_content(json, box);
    gak_json_text(json, "\"");
}

static int gak_json_chain(const GakCallSource *source,
                          const GakCallSource **chain) {
    int count = 0;
    while (source && count < 65) {
        if (source->end < source->start) return 0;
        chain[count++] = source;
        source = source->parent;
    }
    return source || count == 0 ? 0 : count;
}

static void gak_json_label(GakCallJson *json, const GakCallSource **chain, int count) {
    gak_json_text(json, "\"");
    gak_json_metadata_content(json, chain[count - 1]->label);
    for (int index = count - 2; index >= 0 && !json->failed; index--) {
        const GakCallSource *child = chain[index];
        if (child->operation == 2) gak_json_text(json, " patched");
        else if (child->operation == 3) gak_json_text(json, " spliced");
        else if (child->operation != 1) { json->failed = 1; break; }
        gak_json_text(json, "[");
        gak_json_number(json, child->range_start);
        gak_json_text(json, "..");
        gak_json_number(json, child->range_end);
        gak_json_text(json, ")");
        if (child->operation == 3) {
            gak_json_text(json, "->");
            gak_json_number(json, child->inserted_size);
        }
        if (child->address_kind) {
            gak_json_text(json, child->address_kind == 1
                ? " @ PE RVA 0x" : " @ ELF VA 0x");
            gak_json_hex(json, child->address);
        }
    }
    gak_json_text(json, "\"");
}

static void gak_json_origin(GakCallJson *json, const GakCallSource *source) {
    if (!source->parent) { gak_json_metadata_box(json, source->origin); return; }
    gak_json_text(json, "\"");
    if (source->address_kind) {
        gak_json_text(json, source->address_kind == 1
            ? "PE RVA 0x" : "ELF VA 0x");
        gak_json_hex(json, source->address);
        gak_json_text(json, "; ");
    }
    if (source->operation == 1) gak_json_text(json, "view of sha256:");
    else if (source->operation == 2) gak_json_text(json, "patch of sha256:");
    else if (source->operation == 3) gak_json_text(json, "splice of sha256:");
    else { json->failed = 1; return; }
    gak_json_box_content(json, source->parent->sha256);
    gak_json_text(json, " [");
    gak_json_number(json, source->range_start);
    gak_json_text(json, "..");
    gak_json_number(json, source->range_end);
    gak_json_text(json, ")");
    if (source->operation == 3) {
        gak_json_text(json, " -> ");
        gak_json_number(json, source->inserted_size);
        gak_json_text(json, " bytes");
    }
    gak_json_text(json, "\"");
}

static void gak_json_lineage(GakCallJson *json, const GakCallSource **chain, int count) {
    gak_json_text(json, "[");
    for (int index = count - 1; index >= 0 && !json->failed; index--) {
        const GakCallSource *item = chain[index];
        if (index != count - 1) gak_json_text(json, ",");
        if (!item->parent) {
            gak_json_text(json, "{\"operation\":\"capture\",\"origin\":");
            gak_json_metadata_box(json, item->origin);
            gak_json_text(json, ",\"label\":");
            gak_json_metadata_box(json, item->label);
        } else {
            if (item->operation == 1) gak_json_text(json, "{\"operation\":\"view\"");
            else if (item->operation == 2) gak_json_text(json, "{\"operation\":\"patch\"");
            else if (item->operation == 3) gak_json_text(json, "{\"operation\":\"splice\"");
            else { json->failed = 1; break; }
            gak_json_text(json, ",\"parent_sha256\":");
            gak_json_box(json, item->parent->sha256);
            gak_json_text(json, ",\"start\":");
            gak_json_number(json, item->range_start);
            gak_json_text(json, ",\"end\":");
            gak_json_number(json, item->range_end);
            if (item->operation == 1) {
                if (!item->address_kind) gak_json_text(json, ",\"address\":null");
                else {
                    gak_json_text(json, item->address_kind == 1
                        ? ",\"address\":{\"space\":\"pe.rva\",\"value\":\"0x"
                        : ",\"address\":{\"space\":\"elf.va\",\"value\":\"0x");
                    gak_json_hex(json, item->address);
                    gak_json_text(json, "\"}");
                }
            }
            else {
                uint64_t length = item->operation == 2
                    ? item->range_end - item->range_start : item->inserted_size;
                if (item->range_end < item->range_start ||
                    item->range_start > item->end - item->start ||
                    length > item->end - item->start - item->range_start) {
                    json->failed = 1; break;
                }
                const uint8_t *bytes = item->backing + 8 + item->start + item->range_start;
                const uint8_t *hash = gak_native_call_hash(bytes, length);
                gak_json_text(json, ",\"replacement_sha256\":");
                gak_json_box(json, hash);
                if (item->operation == 3) {
                    gak_json_text(json, ",\"inserted_size\":");
                    gak_json_number(json, item->inserted_size);
                }
            }
        }
        gak_json_text(json, ",\"sha256\":");
        gak_json_box(json, item->sha256);
        gak_json_text(json, ",\"size\":");
        gak_json_number(json, item->end - item->start);
        gak_json_text(json, "}");
    }
    gak_json_text(json, "]");
}

static uint32_t gak_call_encode_research(uint8_t tag, uint64_t value) {
    if (!value) { gak_call_result_error("null research result"); return 0; }
    const GakCallObservation *observation = tag == 13
        ? (const GakCallObservation *)(uintptr_t)value : NULL;
    const GakCallSource *source = observation
        ? observation->source : (const GakCallSource *)(uintptr_t)value;
    const GakCallSource *chain[65];
    int count = gak_json_chain(source, chain);
    if (!count) { gak_call_result_error("invalid Source lineage"); return 0; }
    GakCallJson json = {0, 0};
    if (observation) {
        gak_json_text(&json, "{\"$galeikan\":\"Observation\",\"value\":");
        gak_json_number(&json, observation->value);
        gak_json_text(&json, ",\"offset\":");
        gak_json_number(&json, observation->offset);
        gak_json_text(&json, ",\"width\":");
        gak_json_number(&json, observation->width);
        gak_json_text(&json, ",\"decoder\":");
        gak_json_box(&json, observation->decoder);
        gak_json_text(&json, ",\"source\":");
    } else {
        gak_json_text(&json, "{\"$galeikan\":\"Source\",\"label\":");
    }
    gak_json_label(&json, chain, count);
    gak_json_text(&json, ",\"origin\":");
    gak_json_origin(&json, source);
    gak_json_text(&json, ",\"sha256\":");
    gak_json_box(&json, source->sha256);
    if (!observation) {
        gak_json_text(&json, ",\"size\":");
        gak_json_number(&json, source->end - source->start);
    }
    gak_json_text(&json, observation ? ",\"source_lineage\":" : ",\"lineage\":");
    gak_json_lineage(&json, chain, count);
    gak_json_text(&json, "}");
    if (json.failed) { gak_call_result_error("research result exceeds 500000 bytes or is invalid"); return 0; }
    return (uint32_t)json.length;
}

void gak_native_call_result(uint64_t tag, uint64_t value) {
    if (!gak_call_active || gak_call_result_written)
        gak_call_fail("protocol response is not available");
    uint64_t expected_mask = gak_call_arg_count == 64 ? UINT64_MAX :
        ((UINT64_C(1) << gak_call_arg_count) - 1u);
    if (gak_call_read_mask != expected_mask) {
        gak_call_result_error("not all function arguments were read");
        return;
    }

    uint8_t number[8];
    const uint8_t *payload;
    uint32_t length;
    switch (tag) {
    case 1: /* i64 */
    case 2: /* u64 */
        gak_call_put_u64(number, value);
        payload = number;
        length = 8;
        break;
    case 3: /* bool */
        if (value > 1) {
            gak_call_result_error("invalid boolean result");
            return;
        }
        number[0] = (uint8_t)value;
        payload = number;
        length = 1;
        break;
    case 4: /* str */
    case 5: { /* bytes */
        if (!value) {
            gak_call_result_error("null boxed result");
            return;
        }
        const uint8_t *box = (const uint8_t *)(uintptr_t)value;
        uint64_t boxed_length;
        memcpy(&boxed_length, box, 8);
        if (boxed_length > GAK_CALL_MAX_PAYLOAD) {
            gak_call_result_error("result exceeds 500000 bytes");
            return;
        }
        length = (uint32_t)boxed_length;
        payload = box + 8;
        if (tag == 4 && !gak_call_utf8(payload, length)) {
            gak_call_result_error("string result is not valid UTF-8");
            return;
        }
        break;
    }
    case 6: /* List<i64> */
    case 7: /* List<u64> */
    case 8: /* List<bool> */
    case 9: /* List<str> */
    case 10: /* List<bytes> */
        length = gak_call_encode_list((uint8_t)tag, value);
        if (gak_call_result_written) return;
        payload = gak_call_response_payload;
        break;
    case 12: /* Source */
    case 13: /* Observation */
        length = gak_call_encode_research((uint8_t)tag, value);
        if (gak_call_result_written) return;
        payload = gak_call_response_payload;
        break;
    default:
        gak_call_result_error("unsupported result type");
        return;
    }
    if (fflush(stdout) != 0) gak_call_fail("cannot flush program output");
    uint8_t header[13];
    memcpy(header, "GAKRESP1", 8);
    header[8] = (uint8_t)tag;
    gak_call_put_u32(header + 9, length);
    gak_call_write_all(header, sizeof(header));
    gak_call_write_all(payload, length);
    gak_call_result_written = 1;
    if (!gak_native_call_serve_mode) {
        if (gak_close(gak_call_protocol_fd) != 0)
            gak_call_fail("cannot close protocol output");
        gak_call_protocol_fd = -1;
    }
}

void gak_native_call_error(const uint8_t *message, uint64_t length) {
    if (!gak_call_active || !gak_native_call_serve_mode || gak_call_result_written)
        gak_call_fail("session error response is not available");
    static const uint8_t fallback[] = "native runtime error";
    if (!message || !length || length > GAK_CALL_MAX_PAYLOAD ||
        !gak_call_utf8(message, (size_t)length)) {
        message = fallback;
        length = sizeof(fallback) - 1u;
    }
    uint8_t header[13];
    memcpy(header, "GAKRESP1", 8);
    header[8] = 0;
    gak_call_put_u32(header + 9, (uint32_t)length);
    gak_call_write_all(header, sizeof(header));
    gak_call_write_all(message, (size_t)length);
    gak_call_result_written = 1;
}

void gak_native_call_unknown(void) {
    if (!gak_native_call_serve_mode)
        gak_call_fail("unknown or unsupported native function");
    static const uint8_t message[] = "unknown or unsupported native function";
    gak_native_call_error(message, sizeof(message) - 1u);
}
