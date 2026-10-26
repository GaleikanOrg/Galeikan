/* Platform file-handle verification for generated native programs.
 * The language/runtime and binary operations remain in Rust and assembly.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wchar.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#define GAK_MAX_ROOTS 64
#define GAK_MAX_PROCESS_GRANTS 64
#define GAK_MAX_CONNECTION_GRANTS 64
#define GAK_MAX_PATH_BYTES 32768
#define GAK_MAX_SNAPSHOT 536870912ULL
#define GAK_MAX_REGIONS 50000
#define GAK_MAX_THREADS 50000
#define GAK_MAX_CHILDREN 50000
#define GAK_MAX_MAP_BYTES (16u * 1024u * 1024u)

extern uint64_t gak_argc;
extern void *gak_argv;
extern uint64_t gak_source_backing_bytes;
uint8_t *gak_file_error;
static const struct {
    uint64_t length;
    char message[25];
} gak_oom_error = {24, "native allocation failed"};

typedef struct {
    uint8_t *backing;
    uint8_t *label;
    uint8_t *origin;
} GakFileResult;

typedef struct {
    uint64_t pid;
    uint64_t start;
    uint64_t size;
    uint8_t *access;
    uint8_t *label;
    uint64_t image_backed;
} GakRegion;

typedef struct {
    uint64_t count;
    GakRegion *items[GAK_MAX_REGIONS];
} GakRegions;

typedef struct {
    uint64_t count;
    uint8_t *items[];
} GakModules;

#ifdef _WIN32
static wchar_t *gak_roots[GAK_MAX_ROOTS];
wchar_t *gak_python_executable;
#else
static char *gak_roots[GAK_MAX_ROOTS];
char *gak_python_executable;
#endif
static size_t gak_root_count;
static size_t gak_file_metadata_bytes;
static uint32_t gak_process_grants[GAK_MAX_PROCESS_GRANTS];
static size_t gak_process_grant_count;
static int gak_failf(const char *format, ...);
static char *gak_connections[GAK_MAX_CONNECTION_GRANTS];
static size_t gak_connection_count;

int gak_native_net_allowed(const char *authority) {
    for (size_t index = 0; index < gak_connection_count; index++)
        if (strcmp(gak_connections[index], authority) == 0) return 1;
    return 0;
}

static int gak_grant_connection(const char *authority) {
    size_t length = strlen(authority);
    if (!length || length > 512) return gak_failf("invalid connection grant");
    if (gak_connection_count >= GAK_MAX_CONNECTION_GRANTS)
        return gak_failf("too many connection grants");
    char *copy = strdup(authority);
    if (!copy) return gak_failf("native allocation failed");
    gak_connections[gak_connection_count++] = copy;
    return 0;
}

static int gak_process_allowed(uint32_t pid) {
    for (size_t index = 0; index < gak_process_grant_count; index++)
        if (gak_process_grants[index] == pid) return 1;
    return 0;
}

static int gak_account_metadata(size_t bytes) {
    if (bytes > 67108864 || gak_file_metadata_bytes > 67108864 - bytes) return 0;
    gak_file_metadata_bytes += bytes;
    return 1;
}

static uint8_t *gak_box(const char *text, size_t length) {
    if (length > 1024 * 1024 || length > SIZE_MAX - 9) return NULL;
    if (gak_file_metadata_bytes > 67108864 - (length + 9)) return NULL;
    uint8_t *box = malloc(length + 9);
    if (!box) return NULL;
    gak_account_metadata(length + 9);
    uint64_t size = (uint64_t)length;
    memcpy(box, &size, 8);
    memcpy(box + 8, text, length);
    box[length + 8] = 0;
    return box;
}

uint8_t *gak_native_metadata_box(const char *text, size_t length) {
    return gak_box(text, length);
}

static int gak_failf(const char *format, ...) {
    char message[8192];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    if (length < 0) return -1;
    size_t stored = (size_t)length;
    if (stored >= sizeof(message)) stored = sizeof(message) - 1;
    gak_file_error = gak_box(message, stored);
    if (!gak_file_error) gak_file_error = (uint8_t *)&gak_oom_error;
    return -1;
}

static char *gak_cstring(const uint8_t *box) {
    uint64_t length;
    memcpy(&length, box, 8);
    if (length > GAK_MAX_PATH_BYTES) {
        gak_failf("file path exceeds %d bytes", GAK_MAX_PATH_BYTES);
        return NULL;
    }
    if (memchr(box + 8, 0, (size_t)length)) {
        gak_failf("file path contains NUL");
        return NULL;
    }
    char *copy = malloc((size_t)length + 1);
    if (!copy) {
        gak_failf("native allocation failed");
        return NULL;
    }
    memcpy(copy, box + 8, (size_t)length);
    copy[length] = 0;
    return copy;
}

static uint8_t *gak_escaped_box(const char *text) {
    size_t length = strlen(text);
    if (length > SIZE_MAX / 6 - 1) return NULL;
    char *escaped = malloc(length * 6 + 1);
    if (!escaped) return NULL;
    size_t used = 0;
    for (size_t index = 0; index < length; index++) {
        unsigned char ch = (unsigned char)text[index];
        if (ch == '"' || ch == '\\') {
            escaped[used++] = '\\';
            escaped[used++] = (char)ch;
        } else if (ch == '\n' || ch == '\r' || ch == '\t' || ch == 0) {
            escaped[used++] = '\\';
            escaped[used++] = ch == '\n' ? 'n' : ch == '\r' ? 'r' : ch == '\t' ? 't' : '0';
        } else if (ch < 32 || ch == 127) {
            used += (size_t)snprintf(escaped + used, 7, "\\u{%x}", ch);
        } else {
            escaped[used++] = (char)ch;
        }
    }
    uint8_t *box = gak_box(escaped, used);
    free(escaped);
    return box;
}

#ifdef _WIN32
static wchar_t *gak_wide(const char *utf8) {
    size_t length = strlen(utf8);
    if (length > GAK_MAX_PATH_BYTES) return NULL;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, (int)length, NULL, 0);
    if (!count) return NULL;
    wchar_t *wide = calloc((size_t)count + 1, sizeof(wchar_t));
    if (!wide) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, (int)length, wide, count)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static char *gak_utf8(const wchar_t *wide) {
    size_t length = wcslen(wide);
    if (length > GAK_MAX_PATH_BYTES) return NULL;
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length, NULL, 0, NULL, NULL);
    if (!count) return NULL;
    char *utf8 = calloc((size_t)count + 1, 1);
    if (!utf8) return NULL;
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)length, utf8, count, NULL, NULL)) {
        free(utf8);
        return NULL;
    }
    return utf8;
}

static wchar_t *gak_final_path(HANDLE handle) {
    wchar_t *path = calloc(GAK_MAX_PATH_BYTES, sizeof(wchar_t));
    if (!path) return NULL;
    DWORD count = GetFinalPathNameByHandleW(handle, path, GAK_MAX_PATH_BYTES, 0);
    if (!count || count >= GAK_MAX_PATH_BYTES) {
        free(path);
        return NULL;
    }
    return path;
}

static int gak_allowed(const wchar_t *path) {
    for (size_t index = 0; index < gak_root_count; index++) {
        size_t length = wcslen(gak_roots[index]);
        /* Exact case avoids granting a distinct case-sensitive directory. */
        if (wcsncmp(path, gak_roots[index], length) != 0) continue;
        if (gak_roots[index][length - 1] == L'\\' || path[length] == L'\\' || path[length] == 0)
            return 1;
    }
    return 0;
}

static int gak_grant_root(const wchar_t *requested) {
    if (gak_root_count >= GAK_MAX_ROOTS) return gak_failf("too many read directories");
    HANDLE handle = CreateFileW(requested, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) return gak_failf("invalid read directory");
    DWORD attributes = GetFileAttributesW(requested);
    wchar_t *path = gak_final_path(handle);
    CloseHandle(handle);
    if (!path || attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        free(path);
        return gak_failf("invalid read directory");
    }
    gak_roots[gak_root_count++] = path;
    return 0;
}

static int gak_grant_process(const wchar_t *requested) {
    if (gak_process_grant_count >= GAK_MAX_PROCESS_GRANTS)
        return gak_failf("too many process grants");
    if (wcscmp(requested, L"self") == 0) {
        gak_process_grants[gak_process_grant_count++] = GetCurrentProcessId();
        return 0;
    }
    if (!requested[0]) return gak_failf("invalid process grant");
    uint32_t pid = 0;
    for (const wchar_t *digit = requested; *digit; digit++) {
        if (*digit < L'0' || *digit > L'9' || pid > (2147483647u - (uint32_t)(*digit - L'0')) / 10)
            return gak_failf("invalid process grant");
        pid = pid * 10 + (uint32_t)(*digit - L'0');
    }
    if (!pid) return gak_failf("invalid process grant");
    gak_process_grants[gak_process_grant_count++] = pid;
    return 0;
}

int gak_native_init(void) {
    wchar_t **arguments = (wchar_t **)gak_argv;
    size_t count = (size_t)gak_argc;
    wchar_t **filtered = calloc(count + 1, sizeof(*filtered));
    if (!filtered) return gak_failf("native allocation failed");
    size_t kept = 0;
    filtered[kept++] = arguments[0];
    int options = 1;
    for (size_t index = 1; index < count; index++) {
        wchar_t *argument = arguments[index];
        if (options && wcscmp(argument, L"--") == 0) {
            options = 0;
            continue;
        }
        if (options && wcscmp(argument, L"--allow-read") == 0) {
            if (++index >= count) return gak_failf("--allow-read needs a directory");
            if (gak_grant_root(arguments[index]) != 0) return -1;
            continue;
        }
        if (options && wcscmp(argument, L"--allow-connect") == 0) {
            if (++index >= count) return gak_failf("--allow-connect needs a host:port");
            char *authority = gak_utf8(arguments[index]);
            if (!authority) return gak_failf("invalid connection grant");
            int status = gak_grant_connection(authority);
            free(authority);
            if (status != 0) return -1;
            continue;
        }
        if (options && wcscmp(argument, L"--allow-python") == 0) {
            if (++index >= count || !arguments[index][0])
                return gak_failf("--allow-python needs a Python executable");
            if (gak_python_executable)
                return gak_failf("--allow-python may be given only once");
            gak_python_executable = _wcsdup(arguments[index]);
            if (!gak_python_executable) return gak_failf("native allocation failed");
            continue;
        }
        if (options && wcscmp(argument, L"--allow-process") == 0) {
            if (++index >= count) return gak_failf("--allow-process needs a pid or self");
            if (gak_grant_process(arguments[index]) != 0) return -1;
            continue;
        }
        filtered[kept++] = argument;
    }
    gak_argc = (uint64_t)kept;
    gak_argv = filtered;
    return 0;
}

static int gak_absolute(const wchar_t *path) {
    return (path[0] == L'\\' && path[1] == L'\\') ||
        (((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
         path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'));
}

static wchar_t *gak_unverbatim(const wchar_t *path) {
    if (wcsncmp(path, L"\\\\?\\UNC\\", 8) == 0) {
        size_t size = wcslen(path) - 8 + 3;
        wchar_t *plain = calloc(size, sizeof(wchar_t));
        if (plain) swprintf(plain, size, L"\\\\%ls", path + 8);
        return plain;
    }
    if (wcsncmp(path, L"\\\\?\\", 4) == 0) return _wcsdup(path + 4);
    return _wcsdup(path);
}

static wchar_t *gak_requested_path(const char *path, const char *base) {
    wchar_t *raw = gak_wide(path);
    wchar_t *raw_base = gak_wide(base);
    wchar_t *wide = raw ? gak_unverbatim(raw) : NULL;
    wchar_t *wide_base = raw_base ? gak_unverbatim(raw_base) : NULL;
    free(raw);
    free(raw_base);
    if (!wide || !wide_base) {
        free(wide);
        free(wide_base);
        return NULL;
    }
    wchar_t *joined = wide;
    if (!gak_absolute(wide)) {
        size_t size = wcslen(wide_base) + wcslen(wide) + 2;
        joined = calloc(size, sizeof(wchar_t));
        if (joined) swprintf(joined, size, L"%ls\\%ls", wide_base, wide);
        free(wide);
    }
    free(wide_base);
    if (!joined) return NULL;
    wchar_t *full = calloc(GAK_MAX_PATH_BYTES, sizeof(wchar_t));
    if (!full) {
        free(joined);
        return NULL;
    }
    DWORD size = GetFullPathNameW(joined, GAK_MAX_PATH_BYTES, full, NULL);
    free(joined);
    if (!size || size >= GAK_MAX_PATH_BYTES - 8) {
        free(full);
        return NULL;
    }
    size_t needed = (size_t)size + 9;
    wchar_t *verbatim = calloc(needed, sizeof(wchar_t));
    if (!verbatim) {
        free(full);
        return NULL;
    }
    if (full[0] == L'\\' && full[1] == L'\\')
        swprintf(verbatim, needed, L"\\\\?\\UNC\\%ls", full + 2);
    else
        swprintf(verbatim, needed, L"\\\\?\\%ls", full);
    free(full);
    return verbatim;
}

#else
static int gak_allowed(const char *path) {
    for (size_t index = 0; index < gak_root_count; index++) {
        size_t length = strlen(gak_roots[index]);
        if (strncmp(path, gak_roots[index], length) != 0) continue;
        if ((length == 1 && gak_roots[index][0] == '/') || path[length] == '/' || path[length] == 0)
            return 1;
    }
    return 0;
}

static int gak_grant_root(const char *requested) {
    if (gak_root_count >= GAK_MAX_ROOTS) return gak_failf("too many read directories");
    char *path = realpath(requested, NULL);
    struct stat metadata;
    if (!path || stat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
        free(path);
        return gak_failf("invalid read directory: %s", requested);
    }
    gak_roots[gak_root_count++] = path;
    return 0;
}

static int gak_grant_process(const char *requested) {
    if (gak_process_grant_count >= GAK_MAX_PROCESS_GRANTS)
        return gak_failf("too many process grants");
    if (strcmp(requested, "self") == 0) {
        gak_process_grants[gak_process_grant_count++] = (uint32_t)getpid();
        return 0;
    }
    if (!requested[0]) return gak_failf("invalid process grant");
    uint32_t pid = 0;
    for (const char *digit = requested; *digit; digit++) {
        if (*digit < '0' || *digit > '9' || pid > (2147483647u - (uint32_t)(*digit - '0')) / 10)
            return gak_failf("invalid process grant");
        pid = pid * 10 + (uint32_t)(*digit - '0');
    }
    if (!pid) return gak_failf("invalid process grant");
    gak_process_grants[gak_process_grant_count++] = pid;
    return 0;
}

int gak_native_init(void) {
    char **arguments = (char **)gak_argv;
    size_t count = (size_t)gak_argc;
    char **filtered = calloc(count + 1, sizeof(*filtered));
    if (!filtered) return gak_failf("native allocation failed");
    size_t kept = 0;
    filtered[kept++] = arguments[0];
    int options = 1;
    for (size_t index = 1; index < count; index++) {
        char *argument = arguments[index];
        if (options && strcmp(argument, "--") == 0) {
            options = 0;
            continue;
        }
        if (options && strcmp(argument, "--allow-read") == 0) {
            if (++index >= count) return gak_failf("--allow-read needs a directory");
            if (gak_grant_root(arguments[index]) != 0) return -1;
            continue;
        }
        if (options && strcmp(argument, "--allow-connect") == 0) {
            if (++index >= count) return gak_failf("--allow-connect needs a host:port");
            if (gak_grant_connection(arguments[index]) != 0) return -1;
            continue;
        }
        if (options && strcmp(argument, "--allow-python") == 0) {
            if (++index >= count || !arguments[index][0])
                return gak_failf("--allow-python needs a Python executable");
            if (gak_python_executable)
                return gak_failf("--allow-python may be given only once");
            gak_python_executable = strdup(arguments[index]);
            if (!gak_python_executable) return gak_failf("native allocation failed");
            continue;
        }
        if (options && strcmp(argument, "--allow-process") == 0) {
            if (++index >= count) return gak_failf("--allow-process needs a pid or self");
            if (gak_grant_process(arguments[index]) != 0) return -1;
            continue;
        }
        filtered[kept++] = argument;
    }
    gak_argc = (uint64_t)kept;
    gak_argv = filtered;
    return 0;
}

static char *gak_requested_path(const char *path, const char *base) {
    if (path[0] == '/') return strdup(path);
    size_t size = strlen(base) + strlen(path) + 2;
    if (size > GAK_MAX_PATH_BYTES) return NULL;
    char *joined = malloc(size);
    if (joined) snprintf(joined, size, "%s/%s", base, path);
    return joined;
}
#endif

GakFileResult *gak_native_read_file(const uint8_t *path_box, int64_t max, const uint8_t *base_box) {
    gak_file_error = NULL;
    if (max < 0 || (uint64_t)max > GAK_MAX_SNAPSHOT) {
        gak_failf("max_bytes must be between 0 and 536870912");
        return NULL;
    }
    char *label = gak_cstring(path_box);
    char *base = gak_cstring(base_box);
    if (!label || !base) {
        free(label);
        free(base);
        return NULL;
    }
    uint8_t *backing = NULL;
    char *opened_utf8 = NULL;

#ifdef _WIN32
    wchar_t *requested = gak_requested_path(label, base);
    if (!requested) {
        gak_failf("invalid UTF-8 file path or native allocation failed");
        goto failed;
    }
    HANDLE file = CreateFileW(requested, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    free(requested);
    if (file == INVALID_HANDLE_VALUE) {
        gak_failf("cannot open file: %s", label);
        goto failed;
    }
    wchar_t *opened = gak_final_path(file);
    if (!opened) {
        gak_failf("cannot verify opened file path");
        CloseHandle(file);
        goto failed;
    }
    opened_utf8 = gak_utf8(opened);
    if (!gak_allowed(opened)) gak_failf("file access not allowed: %s", opened_utf8 ? opened_utf8 : label);
    free(opened);
    if (gak_file_error || !opened_utf8) {
        if (!gak_file_error) gak_failf("cannot encode opened file path as UTF-8");
        CloseHandle(file);
        goto failed;
    }
    BY_HANDLE_FILE_INFORMATION information;
    if (GetFileType(file) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(file, &information) ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        gak_failf("file is not a regular file: %s", opened_utf8);
        CloseHandle(file);
        goto failed;
    }
#else
    char *requested = gak_requested_path(label, base);
    if (!requested) {
        gak_failf("file path exceeds %d bytes or native allocation failed", GAK_MAX_PATH_BYTES);
        goto failed;
    }
    char *canonical = realpath(requested, NULL);
    if (!canonical) {
        gak_failf("%s: %s", requested, strerror(errno));
        free(requested);
        goto failed;
    }
    free(requested);
    if (!gak_allowed(canonical)) {
        gak_failf("file access not allowed: %s", canonical);
        free(canonical);
        goto failed;
    }
    int file = open(canonical, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (file < 0) {
        gak_failf("%s: %s", canonical, strerror(errno));
        free(canonical);
        goto failed;
    }
    free(canonical);
    char descriptor[64];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", file);
    char opened[GAK_MAX_PATH_BYTES];
    ssize_t opened_size = readlink(descriptor, opened, sizeof(opened) - 1);
    if (opened_size < 0 || (size_t)opened_size >= sizeof(opened) - 1) {
        gak_failf("cannot verify opened file path");
        close(file);
        goto failed;
    }
    opened[opened_size] = 0;
    if (!gak_allowed(opened)) {
        gak_failf("file access not allowed: %s", opened);
        close(file);
        goto failed;
    }
    opened_utf8 = strdup(opened);
    if (!opened_utf8) {
        gak_failf("native allocation failed");
        close(file);
        goto failed;
    }
    struct stat metadata;
    if (fstat(file, &metadata) != 0) {
        gak_failf("cannot inspect opened file: %s", opened_utf8);
        close(file);
        goto failed;
    }
    if (!S_ISREG(metadata.st_mode)) {
        gak_failf("file is not a regular file: %s", opened_utf8);
        close(file);
        goto failed;
    }
#endif

    if (gak_source_backing_bytes > GAK_MAX_SNAPSHOT) {
        gak_failf("native Source backing memory exceeds 512 MiB");
        goto close_file;
    }
    size_t remaining = (size_t)(GAK_MAX_SNAPSHOT - gak_source_backing_bytes);
    size_t limit = (size_t)max < remaining ? (size_t)max : remaining;
    int budget_limited = limit < (size_t)max;
    size_t capacity = limit + 1 < 4096 ? limit + 1 : 4096;
    backing = malloc(capacity + 8);
    if (!backing) {
        gak_failf("native allocation failed");
        goto close_file;
    }
    size_t size = 0;
    for (;;) {
        if (size == capacity) {
            if (capacity == limit + 1) {
                if (budget_limited) gak_failf("native Source backing memory exceeds 512 MiB");
                else gak_failf("LimitExceeded: %s is larger than %lld bytes", opened_utf8, (long long)max);
                goto close_file;
            }
            size_t grown = capacity * 2;
            if (grown > limit + 1) grown = limit + 1;
            uint8_t *expanded = realloc(backing, grown + 8);
            if (!expanded) {
                gak_failf("native allocation failed");
                goto close_file;
            }
            backing = expanded;
            capacity = grown;
        }
        size_t available = capacity - size;
        if (available > 65536) available = 65536;
#ifdef _WIN32
        DWORD received = 0;
        if (!ReadFile(file, backing + 8 + size, (DWORD)available, &received, NULL)) {
            gak_failf("cannot read file: %s", opened_utf8);
            goto close_file;
        }
        size_t count = (size_t)received;
#else
        ssize_t received = read(file, backing + 8 + size, available);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) {
            gak_failf("%s: %s", opened_utf8, strerror(errno));
            goto close_file;
        }
        size_t count = (size_t)received;
#endif
        if (count == 0) break;
        size += count;
        if (size > limit) {
            if (budget_limited) gak_failf("native Source backing memory exceeds 512 MiB");
            else gak_failf("LimitExceeded: %s is larger than %lld bytes", opened_utf8, (long long)max);
            goto close_file;
        }
    }
    uint64_t boxed_size = (uint64_t)size;
    memcpy(backing, &boxed_size, 8);
    uint8_t *exact = realloc(backing, size + 8);
    if (exact) backing = exact;
    GakFileResult *result = malloc(sizeof(*result));
    if (!result) {
        gak_failf("native allocation failed");
        goto close_file;
    }
    size_t origin_size = strlen(opened_utf8) + 6;
    char *origin = malloc(origin_size);
    if (!origin) {
        free(result);
        gak_failf("native allocation failed");
        goto close_file;
    }
    snprintf(origin, origin_size, "file:%s", opened_utf8);
    result->backing = backing;
    result->label = gak_escaped_box(label);
    result->origin = gak_escaped_box(origin);
    free(origin);
    if (!result->label || !result->origin) {
        free(result->label);
        free(result->origin);
        free(result);
        gak_failf("native allocation failed");
        goto close_file;
    }
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
    free(label);
    free(base);
    free(opened_utf8);
    return result;

close_file:
#ifdef _WIN32
    CloseHandle(file);
#else
    close(file);
#endif
failed:
    free(backing);
    free(label);
    free(base);
    free(opened_utf8);
    return NULL;
}

uint64_t gak_native_process_self_pid(void) {
#ifdef _WIN32
    return (uint64_t)GetCurrentProcessId();
#else
    return (uint64_t)getpid();
#endif
}

#ifndef _WIN32
/* 1 = found, 0 = malformed, -1 = I/O error. Child enumeration skips vanished processes. */
static int gak_linux_parent_pid(uint32_t pid, uint32_t *parent, int *error_code) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/status", (unsigned)pid);
    FILE *file = fopen(path, "r");
    if (!file) {
        *error_code = errno;
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "PPid:", 5) != 0) continue;
        char *start = line + 5;
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(start, &end, 10);
        int parse_error = errno;
        while (end && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) end++;
        fclose(file);
        if (parse_error || end == start || !end || *end || value > UINT32_MAX) return 0;
        *parent = (uint32_t)value;
        return 1;
    }
    int error = ferror(file) ? errno : 0;
    fclose(file);
    if (error) {
        *error_code = error;
        return -1;
    }
    return 0;
}
#endif

/* Return parent PID + 1 so zero remains an unambiguous error sentinel. */
uint64_t gak_native_process_parent_pid(uint64_t pid) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return 0;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return 0;
    }
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        gak_failf("cannot read process %u parent: %lu", (unsigned)pid, GetLastError());
        return 0;
    }
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        gak_failf("cannot read process %u parent: %lu", (unsigned)pid, error);
        return 0;
    }
    do {
        if (entry.th32ProcessID == (DWORD)pid) {
            uint64_t result = (uint64_t)entry.th32ParentProcessID + 1u;
            CloseHandle(snapshot);
            return result;
        }
        entry.dwSize = sizeof(entry);
    } while (Process32NextW(snapshot, &entry));
    DWORD error = GetLastError();
    CloseHandle(snapshot);
    if (error == ERROR_NO_MORE_FILES) {
        gak_failf("cannot read process %u parent: process not found", (unsigned)pid);
    } else {
        gak_failf("cannot read process %u parent: %lu", (unsigned)pid, error);
    }
    return 0;
#else
    uint32_t parent = 0;
    int error = 0;
    int status = gak_linux_parent_pid((uint32_t)pid, &parent, &error);
    if (status == 1) return (uint64_t)parent + 1u;
    if (status < 0) {
        gak_failf("cannot read process %u parent: %s", (unsigned)pid, strerror(error));
    } else {
        gak_failf("cannot parse process %u parent", (unsigned)pid);
    }
    return 0;
#endif
}

#ifndef _WIN32
static int gak_process_path_utf8(const unsigned char *bytes, size_t length) {
    size_t index = 0;
    while (index < length) {
        uint32_t codepoint, minimum;
        unsigned continuation;
        unsigned char first = bytes[index++];
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
            unsigned char next = bytes[index++];
            if ((next & 0xc0u) != 0x80u) return 0;
            codepoint = (codepoint << 6) | (next & 0x3fu);
        }
        if (codepoint < minimum || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return 0;
    }
    return 1;
}
#endif

uint8_t *gak_native_process_executable(uint64_t pid) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return NULL;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return NULL;
    }
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!process) {
        gak_failf("cannot read process %u executable: %lu", (unsigned)pid, GetLastError());
        return NULL;
    }
    wchar_t *wide = calloc(GAK_MAX_PATH_BYTES + 1u, sizeof(*wide));
    if (!wide) {
        CloseHandle(process);
        gak_failf("native allocation failed");
        return NULL;
    }
    DWORD size = GAK_MAX_PATH_BYTES;
    BOOL found = QueryFullProcessImageNameW(process, 0, wide, &size);
    DWORD error = found ? 0 : GetLastError();
    CloseHandle(process);
    if (!found) {
        free(wide);
        gak_failf("cannot read process %u executable: %lu", (unsigned)pid, error);
        return NULL;
    }
    wide[size] = 0;
    char *path = gak_utf8(wide);
    free(wide);
    if (!path) {
        gak_failf("process %u executable path is not valid UTF-16", (unsigned)pid);
        return NULL;
    }
    uint8_t *result = gak_box(path, strlen(path));
    free(path);
#else
    char link[64];
    snprintf(link, sizeof(link), "/proc/%u/exe", (unsigned)pid);
    char path[GAK_MAX_PATH_BYTES + 1];
    ssize_t size = readlink(link, path, GAK_MAX_PATH_BYTES);
    if (size < 0) {
        gak_failf("cannot read process %u executable: %s", (unsigned)pid, strerror(errno));
        return NULL;
    }
    if (size == GAK_MAX_PATH_BYTES) {
        gak_failf("process %u executable path exceeds 32767 bytes", (unsigned)pid);
        return NULL;
    }
    if (!gak_process_path_utf8((const unsigned char *)path, (size_t)size)) {
        gak_failf("process %u executable path is not UTF-8", (unsigned)pid);
        return NULL;
    }
    uint8_t *result = gak_box(path, (size_t)size);
#endif
    if (!result) gak_failf("native allocation failed");
    return result;
}

GakFileResult *gak_native_process_snapshot(uint64_t pid, uint64_t address, uint64_t length) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return NULL;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return NULL;
    }
    if (!address || !length || length > 1048576 || address > UINTPTR_MAX - length) {
        gak_failf("process address must be positive and length must be between 1 and 1048576");
        return NULL;
    }
    if (gak_source_backing_bytes > GAK_MAX_SNAPSHOT - length) {
        gak_failf("native Source backing memory exceeds 512 MiB");
        return NULL;
    }
    uint8_t *backing = malloc((size_t)length + 8);
    if (!backing) {
        gak_failf("native allocation failed");
        return NULL;
    }
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (!process) {
        gak_failf("cannot open process %llu for memory reading: %lu",
                  (unsigned long long)pid, GetLastError());
        free(backing);
        return NULL;
    }
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(process, (const void *)(uintptr_t)address,
                                backing + 8, (SIZE_T)length, &read);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(process);
    if (!ok) {
        gak_failf("cannot read process %llu memory: %lu", (unsigned long long)pid, error);
        free(backing);
        return NULL;
    }
    size_t received = (size_t)read;
#else
    struct iovec local = {backing + 8, (size_t)length};
    struct iovec remote = {(void *)(uintptr_t)address, (size_t)length};
    ssize_t read = process_vm_readv((pid_t)pid, &local, 1, &remote, 1, 0);
    if (read < 0) {
        gak_failf("cannot read process %llu memory: %s", (unsigned long long)pid, strerror(errno));
        free(backing);
        return NULL;
    }
    size_t received = (size_t)read;
#endif
    if (received != (size_t)length) {
        gak_failf("process %llu memory read was incomplete: %zu of %llu bytes",
                  (unsigned long long)pid, received, (unsigned long long)length);
        free(backing);
        return NULL;
    }
    memcpy(backing, &length, 8);
    char label[128];
    char origin[192];
    snprintf(label, sizeof(label), "process %llu @ 0x%llx",
             (unsigned long long)pid, (unsigned long long)address);
    snprintf(origin, sizeof(origin), "%s (%llu bytes requested)",
             label, (unsigned long long)length);
    GakFileResult *result = malloc(sizeof(*result));
    if (!result) {
        free(backing);
        gak_failf("native allocation failed");
        return NULL;
    }
    result->backing = backing;
    result->label = gak_escaped_box(label);
    result->origin = gak_escaped_box(origin);
    if (!result->label || !result->origin) {
        free(result->label);
        free(result->origin);
        free(result);
        free(backing);
        gak_failf("native allocation failed");
        return NULL;
    }
    return result;
}

static void gak_regions_free(GakRegions *regions) {
    if (!regions) return;
    for (uint64_t index = 0; index < regions->count; index++) {
        GakRegion *region = regions->items[index];
        free(region->access);
        free(region->label);
        free(region);
    }
    free(regions);
}

static int gak_regions_append(GakRegions *regions, uint32_t pid, uint64_t start,
                              uint64_t size, const char *access, const char *label,
                              int image_backed) {
    if (regions->count >= GAK_MAX_REGIONS)
        return gak_failf("process memory map exceeds %d regions", GAK_MAX_REGIONS);
    if (!gak_account_metadata(sizeof(GakRegion)))
        return gak_failf("native metadata memory exceeds 64 MiB");
    GakRegion *region = calloc(1, sizeof(*region));
    if (!region) return gak_failf("native allocation failed");
    region->pid = pid;
    region->start = start;
    region->size = size;
    region->image_backed = image_backed ? 1 : 0;
    region->access = gak_box(access, strlen(access));
    region->label = gak_box(label, strlen(label));
    if (!region->access || !region->label) {
        free(region->access);
        free(region->label);
        free(region);
        return gak_failf("native allocation failed");
    }
    regions->items[regions->count++] = region;
    return 0;
}

#ifdef _WIN32
static const char *gak_windows_access(DWORD protection) {
    if (protection & PAGE_GUARD) return "---";
    switch (protection & 0xff) {
        case PAGE_READONLY: return "r--";
        case PAGE_READWRITE:
        case PAGE_WRITECOPY: return "rw-";
        case PAGE_EXECUTE: return "--x";
        case PAGE_EXECUTE_READ: return "r-x";
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return "rwx";
        default: return "---";
    }
}

static int gak_collect_regions(uint32_t pid, int images_only, GakRegions *regions) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process)
        return gak_failf("cannot open process %u for memory-map query: %lu", pid, GetLastError());
    uintptr_t address = 0;
    for (;;) {
        MEMORY_BASIC_INFORMATION information;
        SIZE_T returned = VirtualQueryEx(process, (const void *)address,
                                          &information, sizeof(information));
        if (!returned) {
            DWORD error = GetLastError();
            if (error == ERROR_INVALID_PARAMETER) break;
            CloseHandle(process);
            return gak_failf("cannot query process %u memory map: %lu", pid, error);
        }
        if (returned != sizeof(information) || !information.RegionSize ||
            (uintptr_t)information.BaseAddress > UINTPTR_MAX - information.RegionSize ||
            (uintptr_t)information.BaseAddress + information.RegionSize <= address) {
            CloseHandle(process);
            return gak_failf("invalid process memory-map entry");
        }
        uintptr_t start = (uintptr_t)information.BaseAddress;
        if (information.State == MEM_COMMIT) {
            int image_backed = information.Type == MEM_IMAGE;
            const char *access = gak_windows_access(information.Protect);
            if (!images_only || (image_backed && access[2] == 'x')) {
                char *label_owned = NULL;
                const char *label = "other";
                if (image_backed) {
                    wchar_t wide[GAK_MAX_PATH_BYTES];
                    DWORD length = K32GetMappedFileNameW(process, information.BaseAddress,
                                                           wide, GAK_MAX_PATH_BYTES);
                    if (length && length < GAK_MAX_PATH_BYTES) {
                        wide[length] = 0;
                        label_owned = gak_utf8(wide);
                    }
                    label = label_owned ? label_owned : "image";
                } else if (information.Type == MEM_MAPPED) {
                    label = "mapped";
                } else if (information.Type == MEM_PRIVATE) {
                    label = "private";
                }
                int status = gak_regions_append(regions, pid, start,
                                                information.RegionSize, access, label, image_backed);
                free(label_owned);
                if (status != 0) {
                    CloseHandle(process);
                    return -1;
                }
            }
        }
        address = start + information.RegionSize;
    }
    CloseHandle(process);
    return 0;
}
#else
static int gak_collect_regions(uint32_t pid, int images_only, GakRegions *regions) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *file = fopen(path, "rb");
    if (!file) return gak_failf("cannot open %s: %s", path, strerror(errno));
    char *content = malloc(GAK_MAX_MAP_BYTES + 2);
    if (!content) {
        fclose(file);
        return gak_failf("native allocation failed");
    }
    size_t size = fread(content, 1, GAK_MAX_MAP_BYTES + 1, file);
    int read_error = ferror(file);
    fclose(file);
    if (read_error || size > GAK_MAX_MAP_BYTES) {
        free(content);
        return gak_failf("process memory map exceeds 16 MiB or could not be read");
    }
    content[size] = 0;
    char *cursor = content;
    int status = 0;
    while (*cursor) {
        char *newline = strchr(cursor, '\n');
        if (newline) *newline = 0;
        unsigned long long start, end, offset, inode;
        char rights[5] = {0};
        char device[32];
        int label_offset = 0;
        int fields = sscanf(cursor, "%llx-%llx %4s %llx %31s %llu %n",
                            &start, &end, rights, &offset, device, &inode, &label_offset);
        if (fields != 6 || !label_offset || strlen(rights) != 4 ||
            start >= end || end > UINTPTR_MAX ||
            (rights[0] != 'r' && rights[0] != '-') ||
            (rights[1] != 'w' && rights[1] != '-') ||
            (rights[2] != 'x' && rights[2] != '-')) {
            status = gak_failf("malformed process memory map");
            break;
        }
        char *label = cursor + label_offset;
        while (*label == ' ' || *label == '\t') label++;
        int image_backed = inode != 0 && label[0] == '/';
        if (!images_only || (image_backed && rights[2] == 'x')) {
            char access[4] = {rights[0], rights[1], rights[2], 0};
            status = gak_regions_append(regions, pid, start, end - start,
                                        access, label, image_backed);
            if (status != 0) break;
        }
        if (!newline) break;
        cursor = newline + 1;
    }
    free(content);
    return status;
}
#endif

GakRegions *gak_native_process_regions(uint64_t pid, uint64_t images_only) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return NULL;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return NULL;
    }
    if (!gak_account_metadata(sizeof(GakRegions))) {
        gak_failf("native metadata memory exceeds 64 MiB");
        return NULL;
    }
    GakRegions *regions = calloc(1, sizeof(*regions));
    if (!regions) {
        gak_failf("native allocation failed");
        return NULL;
    }
    if (gak_collect_regions((uint32_t)pid, images_only != 0, regions) != 0) {
        gak_regions_free(regions);
        return NULL;
    }
    return regions;
}

GakModules *gak_native_process_modules(uint64_t pid) {
    GakRegions *regions = gak_native_process_regions(pid, 1);
    if (!regions) return NULL;
    size_t capacity = sizeof(GakModules) + (size_t)regions->count * sizeof(uint8_t *);
    if (!gak_account_metadata(capacity)) {
        gak_regions_free(regions);
        gak_failf("native metadata memory exceeds 64 MiB");
        return NULL;
    }
    GakModules *modules = calloc(1, capacity);
    if (!modules) {
        gak_regions_free(regions);
        gak_failf("native allocation failed");
        return NULL;
    }
    for (uint64_t index = 0; index < regions->count; index++) {
        const char *label = (const char *)(regions->items[index]->label + 8);
        if (!*label || strcmp(label, "image") == 0) continue;
        int found = 0;
        for (uint64_t previous = 0; previous < modules->count; previous++) {
            const char *existing = (const char *)(modules->items[previous] + 8);
#ifdef _WIN32
            if (_stricmp(label, existing) == 0) {
#else
            if (strcmp(label, existing) == 0) {
#endif
                found = 1;
                break;
            }
        }
        if (found) continue;
        uint8_t *boxed = gak_box(label, strlen(label));
        if (!boxed) {
            for (uint64_t previous = 0; previous < modules->count; previous++)
                free(modules->items[previous]);
            free(modules);
            gak_regions_free(regions);
            gak_failf("native allocation failed");
            return NULL;
        }
        modules->items[modules->count++] = boxed;
    }
    gak_regions_free(regions);
    return modules;
}

static int gak_thread_id_compare(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return (a > b) - (a < b);
}

uint64_t *gak_native_process_children(uint64_t pid) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return NULL;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return NULL;
    }
    uint32_t *ids = malloc(GAK_MAX_CHILDREN * sizeof(*ids));
    if (!ids) {
        gak_failf("native allocation failed");
        return NULL;
    }
    size_t count = 0;
#ifdef _WIN32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        free(ids);
        gak_failf("cannot enumerate process %u children: %lu", (unsigned)pid, GetLastError());
        return NULL;
    }
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        free(ids);
        gak_failf("cannot enumerate process %u children: %lu", (unsigned)pid, error);
        return NULL;
    }
    int target_seen = 0;
    do {
        if (entry.th32ProcessID == (DWORD)pid) target_seen = 1;
        if (entry.th32ParentProcessID == (DWORD)pid && entry.th32ProcessID) {
            if (count >= GAK_MAX_CHILDREN) {
                CloseHandle(snapshot);
                free(ids);
                gak_failf("process child list exceeds %u children", GAK_MAX_CHILDREN);
                return NULL;
            }
            ids[count++] = entry.th32ProcessID;
        }
        entry.dwSize = sizeof(entry);
    } while (Process32NextW(snapshot, &entry));
    DWORD error = GetLastError();
    CloseHandle(snapshot);
    if (error != ERROR_NO_MORE_FILES || !target_seen) {
        free(ids);
        if (!target_seen && error == ERROR_NO_MORE_FILES)
            gak_failf("cannot enumerate process %u children: process not found", (unsigned)pid);
        else
            gak_failf("cannot enumerate process %u children: %lu", (unsigned)pid, error);
        return NULL;
    }
#else
    uint32_t ignored_parent = 0;
    int parent_error = 0;
    int target_status = gak_linux_parent_pid((uint32_t)pid, &ignored_parent, &parent_error);
    if (target_status != 1) {
        free(ids);
        if (target_status < 0)
            gak_failf("cannot enumerate process %u children: %s", (unsigned)pid, strerror(parent_error));
        else
            gak_failf("cannot enumerate process %u children: invalid process status", (unsigned)pid);
        return NULL;
    }
    DIR *directory = opendir("/proc");
    if (!directory) {
        free(ids);
        gak_failf("cannot enumerate process %u children: %s", (unsigned)pid, strerror(errno));
        return NULL;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            int error = errno;
            closedir(directory);
            if (error) {
                free(ids);
                gak_failf("cannot enumerate process %u children: %s", (unsigned)pid, strerror(error));
                return NULL;
            }
            break;
        }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char *end = NULL;
        unsigned long child = strtoul(entry->d_name, &end, 10);
        if (errno || !end || *end || !child || child > 2147483647u) continue;
        uint32_t parent = 0;
        int ignored_error = 0;
        if (gak_linux_parent_pid((uint32_t)child, &parent, &ignored_error) != 1 || parent != pid)
            continue;
        if (count >= GAK_MAX_CHILDREN) {
            closedir(directory);
            free(ids);
            gak_failf("process child list exceeds %u children", GAK_MAX_CHILDREN);
            return NULL;
        }
        ids[count++] = (uint32_t)child;
    }
#endif
    qsort(ids, count, sizeof(*ids), gak_thread_id_compare);
    size_t unique = 0;
    for (size_t index = 0; index < count; index++) {
        if (unique == 0 || ids[index] != ids[unique - 1]) ids[unique++] = ids[index];
    }
    size_t bytes = (unique + 1) * sizeof(uint64_t);
    if (!gak_account_metadata(bytes)) {
        free(ids);
        gak_failf("native metadata memory exceeds 64 MiB");
        return NULL;
    }
    uint64_t *result = malloc(bytes);
    if (!result) {
        free(ids);
        gak_failf("native allocation failed");
        return NULL;
    }
    result[0] = unique;
    for (size_t index = 0; index < unique; index++) result[index + 1] = ids[index];
    free(ids);
    return result;
}

uint64_t *gak_native_process_thread_ids(uint64_t pid) {
    gak_file_error = NULL;
    if (!pid || pid > 2147483647u) {
        gak_failf("pid must be between 1 and 2147483647");
        return NULL;
    }
    if (!gak_process_allowed((uint32_t)pid)) {
        gak_failf("process access not allowed: %llu", (unsigned long long)pid);
        return NULL;
    }
    uint32_t *ids = malloc(GAK_MAX_THREADS * sizeof(*ids));
    if (!ids) {
        gak_failf("native allocation failed");
        return NULL;
    }
    size_t count = 0;
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!process) {
        free(ids);
        gak_failf("cannot enumerate process %u threads: %lu", (unsigned)pid, GetLastError());
        return NULL;
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        CloseHandle(process);
        free(ids);
        gak_failf("cannot enumerate process %u threads: %lu", (unsigned)pid, error);
        return NULL;
    }
    THREADENTRY32 entry = {0};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) {
        DWORD error = GetLastError();
        CloseHandle(snapshot);
        CloseHandle(process);
        free(ids);
        gak_failf("cannot enumerate process %u threads: %lu", (unsigned)pid, error);
        return NULL;
    }
    do {
        if (entry.th32OwnerProcessID == (DWORD)pid && entry.th32ThreadID) {
            if (count >= GAK_MAX_THREADS) {
                CloseHandle(snapshot);
                CloseHandle(process);
                free(ids);
                gak_failf("process thread list exceeds %u threads", GAK_MAX_THREADS);
                return NULL;
            }
            ids[count++] = entry.th32ThreadID;
        }
        entry.dwSize = sizeof(entry);
    } while (Thread32Next(snapshot, &entry));
    DWORD enumeration_error = GetLastError();
    CloseHandle(snapshot);
    CloseHandle(process);
    if (enumeration_error != ERROR_NO_MORE_FILES) {
        free(ids);
        gak_failf("cannot enumerate process %u threads: %lu", (unsigned)pid, enumeration_error);
        return NULL;
    }
#else
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/task", (unsigned)pid);
    DIR *directory = opendir(path);
    if (!directory) {
        free(ids);
        gak_failf("cannot enumerate process %u threads: %s", (unsigned)pid, strerror(errno));
        return NULL;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            int error = errno;
            closedir(directory);
            if (error) {
                free(ids);
                gak_failf("cannot enumerate process %u threads: %s", (unsigned)pid, strerror(error));
                return NULL;
            }
            break;
        }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char *end = NULL;
        unsigned long id = strtoul(entry->d_name, &end, 10);
        if (errno || !end || *end || !id || id > 2147483647u) continue;
        if (count >= GAK_MAX_THREADS) {
            closedir(directory);
            free(ids);
            gak_failf("process thread list exceeds %u threads", GAK_MAX_THREADS);
            return NULL;
        }
        ids[count++] = (uint32_t)id;
    }
#endif
    qsort(ids, count, sizeof(*ids), gak_thread_id_compare);
    size_t unique = 0;
    for (size_t index = 0; index < count; index++) {
        if (unique == 0 || ids[index] != ids[unique - 1]) ids[unique++] = ids[index];
    }
    if (!unique) {
        free(ids);
        gak_failf("process %u has no visible threads", (unsigned)pid);
        return NULL;
    }
    size_t bytes = (unique + 1) * sizeof(uint64_t);
    if (!gak_account_metadata(bytes)) {
        free(ids);
        gak_failf("native metadata memory exceeds 64 MiB");
        return NULL;
    }
    uint64_t *result = malloc(bytes);
    if (!result) {
        free(ids);
        gak_failf("native allocation failed");
        return NULL;
    }
    result[0] = unique;
    for (size_t index = 0; index < unique; index++) result[index + 1] = ids[index];
    free(ids);
    return result;
}

GakRegion *gak_native_process_at(GakRegions *regions, int64_t index) {
    gak_file_error = NULL;
    if (!regions || index < 0 || (uint64_t)index >= regions->count) {
        gak_failf("region index out of range");
        return NULL;
    }
    return regions->items[index];
}

GakRegion *gak_native_process_locate(GakRegions *regions, uint64_t address) {
    gak_file_error = NULL;
    if (!regions) {
        gak_failf("invalid process regions");
        return NULL;
    }
    for (uint64_t index = 0; index < regions->count; index++) {
        GakRegion *region = regions->items[index];
        if (address >= region->start && address - region->start < region->size)
            return region;
    }
    gak_failf("no process region contains address");
    return NULL;
}

uint64_t gak_native_region_offset(GakRegion *region, uint64_t address) {
    gak_file_error = NULL;
    if (!region || address < region->start || address - region->start >= region->size) {
        gak_failf("address is outside process region");
        return UINT64_MAX;
    }
    return address - region->start;
}

uint64_t gak_native_region_address(GakRegion *region, uint64_t offset) {
    gak_file_error = NULL;
    if (!region || offset >= region->size) {
        gak_failf("offset is outside process region");
        return UINT64_MAX;
    }
    if (region->start > UINTPTR_MAX - offset) {
        gak_failf("process region address overflow");
        return UINT64_MAX;
    }
    return region->start + offset;
}

static const char *gak_region_basename(GakRegion *region) {
    const char *label = (const char *)(region->label + 8);
    const char *name = label;
    for (const char *cursor = label; *cursor; cursor++)
        if (*cursor == '/' || *cursor == '\\') name = cursor + 1;
    return *name ? name : "region";
}

uint8_t *gak_native_region_escaped_label(GakRegion *region) {
    gak_file_error = NULL;
    uint8_t *escaped = gak_escaped_box((const char *)(region->label + 8));
    if (!escaped) gak_failf("native allocation failed");
    return escaped;
}

uint8_t *gak_native_region_reference(GakRegion *region, uint64_t address) {
    uint64_t offset = gak_native_region_offset(region, address);
    if (offset == UINT64_MAX) return NULL;
    char reference[GAK_MAX_PATH_BYTES + 128];
    int length = snprintf(reference, sizeof(reference), "%s@%llu:0x%llx+0x%llx",
                          gak_region_basename(region), (unsigned long long)region->pid,
                          (unsigned long long)region->start, (unsigned long long)offset);
    if (length < 0 || (size_t)length >= sizeof(reference)) {
        gak_failf("process region reference exceeds limit");
        return NULL;
    }
    uint8_t *boxed = gak_box(reference, (size_t)length);
    if (!boxed) gak_failf("native allocation failed");
    return boxed;
}

uint64_t gak_native_region_resolve(GakRegion *region, const uint8_t *reference) {
    gak_file_error = NULL;
    if (!region || !reference) {
        gak_failf("invalid process region reference");
        return UINT64_MAX;
    }
    char prefix[GAK_MAX_PATH_BYTES + 128];
    int prefix_length = snprintf(prefix, sizeof(prefix), "%s@%llu:0x%llx+0x",
                                 gak_region_basename(region), (unsigned long long)region->pid,
                                 (unsigned long long)region->start);
    uint64_t reference_length;
    memcpy(&reference_length, reference, 8);
    if (prefix_length < 0 || (size_t)prefix_length >= sizeof(prefix) ||
        reference_length <= (uint64_t)prefix_length ||
        reference_length - (uint64_t)prefix_length > 16 ||
        memcmp(reference + 8, prefix, (size_t)prefix_length) != 0) {
        gak_failf("address reference does not match process region");
        return UINT64_MAX;
    }
    uint64_t offset = 0;
    for (uint64_t index = (uint64_t)prefix_length; index < reference_length; index++) {
        unsigned char digit = reference[8 + index];
        if (digit >= '0' && digit <= '9') digit -= '0';
        else if (digit >= 'a' && digit <= 'f') digit = (unsigned char)(digit - 'a' + 10);
        else if (digit >= 'A' && digit <= 'F') digit = (unsigned char)(digit - 'A' + 10);
        else {
            gak_failf("address reference does not match process region");
            return UINT64_MAX;
        }
        offset = (offset << 4) | digit;
    }
    return gak_native_region_address(region, offset);
}

GakFileResult *gak_native_process_snapshot_region(GakRegion *region,
                                                   uint64_t offset, uint64_t length) {
    gak_file_error = NULL;
    if (!region || offset > region->size || length > region->size - offset) {
        gak_failf("snapshot exceeds region boundaries");
        return NULL;
    }
    if (region->access[8] != 'r') {
        gak_failf("region is not marked readable");
        return NULL;
    }
    uint64_t address = gak_native_region_address(region, offset);
    if (address == UINT64_MAX) return NULL;
    GakFileResult *result = gak_native_process_snapshot(region->pid, address, length);
    if (!result) return NULL;
    uint8_t *escaped_label = gak_escaped_box((const char *)(region->label + 8));
    if (!escaped_label) goto metadata_failed;
    uint64_t escaped_length;
    memcpy(&escaped_length, escaped_label, 8);
    if (escaped_length > SIZE_MAX - 256) {
        free(escaped_label);
        goto metadata_failed;
    }
    size_t capacity = (size_t)escaped_length + 256;
    char *origin = malloc(capacity);
    if (!origin) {
        free(escaped_label);
        goto metadata_failed;
    }
    int written = snprintf(origin, capacity,
                           "process %llu @ 0x%llx (region \"%s\", access %s, %llu bytes requested)",
                           (unsigned long long)region->pid, (unsigned long long)address,
                           (const char *)(escaped_label + 8),
                           (const char *)(region->access + 8), (unsigned long long)length);
    free(escaped_label);
    if (written < 0 || (size_t)written >= capacity) {
        free(origin);
        goto metadata_failed;
    }
    uint8_t *boxed_origin = gak_escaped_box(origin);
    free(origin);
    if (!boxed_origin) goto metadata_failed;
    free(result->origin);
    result->origin = boxed_origin;
    return result;

metadata_failed:
    free(result->backing);
    free(result->label);
    free(result->origin);
    free(result);
    gak_failf("native allocation failed");
    return NULL;
}

GakFileResult *gak_native_process_snapshot_at(GakRegions *regions,
                                               uint64_t address, uint64_t length) {
    GakRegion *region = gak_native_process_locate(regions, address);
    if (!region) return NULL;
    return gak_native_process_snapshot_region(region, address - region->start, length);
}

GakFileResult *gak_native_process_snapshot_ref(GakRegion *region,
                                                const uint8_t *reference, uint64_t length) {
    uint64_t address = gak_native_region_resolve(region, reference);
    if (address == UINT64_MAX) return NULL;
    return gak_native_process_snapshot_region(region, address - region->start, length);
}
