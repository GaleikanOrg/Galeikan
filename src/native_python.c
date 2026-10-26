#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#define GAK_PY_LIMIT 1048576
#define GAK_PY_ARGS 64
#define GAK_PY_TIMEOUT_MS 10000
#define GAK_PY_MEMORY_LIMIT (64u * 1024u * 1024u)

/* The compiler replaces this marker with the bounded Python runner bytes. */
static const char gak_python_runner[] = { __GAK_PYTHON_RUNNER_BYTES__, 0 };

#ifdef _WIN32
extern wchar_t *gak_python_executable;
static HANDLE gak_py_input;
static HANDLE gak_py_output;
static PROCESS_INFORMATION gak_py_process;
#else
extern char *gak_python_executable;
static int gak_py_input = -1;
static int gak_py_output = -1;
static pid_t gak_py_pid = -1;
#endif

typedef struct {
    uint64_t kind;
    uint64_t value;
} GakPythonArgument;

typedef struct {
    char operation;
    const uint8_t *module;
    const uint8_t *digest;
    const uint8_t *function;
    uint64_t expected;
    size_t count;
    GakPythonArgument args[GAK_PY_ARGS];
} GakPythonRequest;

typedef struct {
    uint64_t kind;
    uint64_t value;
} GakPythonResult;

uint8_t *gak_python_error;
static int gak_py_started;
static size_t gak_py_allocated;

static uint8_t *gak_py_box(const char *data, size_t size) {
    if (size > GAK_PY_LIMIT || gak_py_allocated > GAK_PY_MEMORY_LIMIT - 8 ||
        size > GAK_PY_MEMORY_LIMIT - 8 - gak_py_allocated) return NULL;
    uint8_t *box = malloc(size + 8);
    if (!box) return NULL;
    gak_py_allocated += size + 8;
    uint64_t length = (uint64_t)size;
    memcpy(box, &length, 8);
    memcpy(box + 8, data, size);
    return box;
}

static void gak_py_fail(const char *format, ...) {
    char message[4096];
    va_list args;
    va_start(args, format);
    int size = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (size < 0) size = 0;
    if ((size_t)size >= sizeof(message)) size = (int)sizeof(message) - 1;
    gak_python_error = gak_py_box(message, (size_t)size);
    if (!gak_python_error) {
        static const struct { uint64_t size; char text[25]; } oom = {24, "native allocation failed"};
        gak_python_error = (uint8_t *)&oom;
    }
}

static int gak_py_hex(char *target, size_t available, const uint8_t *source, size_t size) {
    static const char digits[] = "0123456789abcdef";
    if (size > available / 2) return -1;
    for (size_t index = 0; index < size; index++) {
        target[index * 2] = digits[source[index] >> 4];
        target[index * 2 + 1] = digits[source[index] & 15];
    }
    return (int)(size * 2);
}

static int gak_py_nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int gak_py_unhex(uint8_t *target, const char *source, size_t length) {
    if (length & 1) return -1;
    for (size_t index = 0; index < length; index += 2) {
        int high = gak_py_nibble(source[index]);
        int low = gak_py_nibble(source[index + 1]);
        if (high < 0 || low < 0) return -1;
        target[index / 2] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int gak_py_append(char *buffer, size_t *used, const char *value, size_t length) {
    if (length > GAK_PY_LIMIT - *used) return -1;
    memcpy(buffer + *used, value, length);
    *used += length;
    return 0;
}

static int gak_py_append_hex(char *buffer, size_t *used, const uint8_t *value, size_t length) {
    if (length > (GAK_PY_LIMIT - *used) / 2) return -1;
    int size = gak_py_hex(buffer + *used, GAK_PY_LIMIT - *used, value, length);
    if (size < 0) return -1;
    *used += (size_t)size;
    return 0;
}

static uint64_t gak_py_length(const uint8_t *box) {
    uint64_t size;
    memcpy(&size, box, 8);
    return size;
}

void *gak_python_request_new(const uint8_t *module, const uint8_t *digest,
                             const uint8_t *function, uint64_t expected) {
    gak_python_error = NULL;
    if (expected < 1 || expected > 10) {
        gak_py_fail("invalid native Python result type");
        return NULL;
    }
    GakPythonRequest *request = calloc(1, sizeof(*request));
    if (!request) {
        gak_py_fail("native allocation failed");
        return NULL;
    }
    request->module = module;
    request->digest = digest;
    request->function = function;
    request->expected = expected;
    request->operation = 'C';
    return request;
}

void *gak_python_request_get(const uint8_t *module, const uint8_t *digest,
                             const uint8_t *name, uint64_t expected) {
    GakPythonRequest *request = gak_python_request_new(module, digest, name, expected);
    if (request) request->operation = 'G';
    return request;
}

void *gak_python_request_arg(void *pointer, uint64_t kind, uint64_t value) {
    GakPythonRequest *request = pointer;
    if (!request || request->count >= GAK_PY_ARGS || kind < 1 || kind > 10) {
        gak_py_fail("invalid native Python argument");
        return NULL;
    }
    request->args[request->count++] = (GakPythonArgument){kind, value};
    return request;
}

static char gak_py_kind(uint64_t kind) {
    switch (kind) {
        case 1: return 'i';
        case 2: return 'u';
        case 3: return 'b';
        case 4: return 's';
        case 5: return 'x';
        case 6: return 'I';
        case 7: return 'U';
        case 8: return 'B';
        case 9: return 'S';
        case 10: return 'X';
        default: return 0;
    }
}

static int gak_py_append_u32(char *buffer, size_t *used, uint32_t value) {
    uint8_t little[4];
    for (size_t byte = 0; byte < 4; byte++) little[byte] = (uint8_t)(value >> (byte * 8));
    return gak_py_append_hex(buffer, used, little, sizeof(little));
}

static int gak_py_append_u64(char *buffer, size_t *used, uint64_t value) {
    uint8_t little[8];
    for (size_t byte = 0; byte < 8; byte++) little[byte] = (uint8_t)(value >> (byte * 8));
    return gak_py_append_hex(buffer, used, little, sizeof(little));
}

static int gak_py_append_list(char *buffer, size_t *used, uint64_t kind, uint64_t value) {
    const uint64_t *list = (const uint64_t *)(uintptr_t)value;
    if (!list || list[0] > 100000 || gak_py_append_u32(buffer, used, (uint32_t)list[0]) < 0)
        return -1;
    for (uint64_t index = 0; index < list[0]; index++) {
        uint64_t item = list[index + 1];
        if (kind == 6 || kind == 7) {
            if (gak_py_append_u64(buffer, used, item) < 0) return -1;
        } else if (kind == 8) {
            if (item > 1) return -1;
            uint8_t flag = (uint8_t)item;
            if (gak_py_append_hex(buffer, used, &flag, 1) < 0) return -1;
        } else {
            const uint8_t *box = (const uint8_t *)(uintptr_t)item;
            if (!box) return -1;
            uint64_t length = gak_py_length(box);
            if (length > 500000 || gak_py_append_u32(buffer, used, (uint32_t)length) < 0 ||
                gak_py_append_hex(buffer, used, box + 8, (size_t)length) < 0) return -1;
        }
    }
    return 0;
}

static char *gak_py_encode(const GakPythonRequest *request, size_t *length) {
    char *buffer = malloc(GAK_PY_LIMIT + 1);
    if (!buffer) return NULL;
    size_t used = 0;
    char operation[2] = {request->operation, '\t'};
    if ((request->operation != 'C' && request->operation != 'G') ||
        (request->operation == 'G' && request->count != 0) ||
        gak_py_append(buffer, &used, operation, sizeof(operation)) < 0 ||
        gak_py_append_hex(buffer, &used, request->module + 8, (size_t)gak_py_length(request->module)) < 0 ||
        gak_py_append(buffer, &used, "\t", 1) < 0 ||
        gak_py_append(buffer, &used, (const char *)request->digest + 8,
                      (size_t)gak_py_length(request->digest)) < 0 ||
        gak_py_append(buffer, &used, "\t", 1) < 0 ||
        gak_py_append_hex(buffer, &used, request->function + 8,
                          (size_t)gak_py_length(request->function)) < 0) goto failed;
    char count[32];
    int count_length = snprintf(count, sizeof(count), "\t%c\t%zu", gak_py_kind(request->expected), request->count);
    if (count_length < 0 || (size_t)count_length >= sizeof(count) ||
        gak_py_append(buffer, &used, count, (size_t)count_length) < 0) goto failed;
    for (size_t index = 0; index < request->count; index++) {
        GakPythonArgument arg = request->args[index];
        char prefix[3] = {'\t', gak_py_kind(arg.kind), ':'};
        if (gak_py_append(buffer, &used, prefix, 3) < 0) goto failed;
        if (arg.kind >= 6) {
            if (gak_py_append_list(buffer, &used, arg.kind, arg.value) < 0) goto failed;
        } else if (arg.kind == 4 || arg.kind == 5) {
            const uint8_t *box = (const uint8_t *)(uintptr_t)arg.value;
            if (!box || gak_py_append_hex(buffer, &used, box + 8,
                                           (size_t)gak_py_length(box)) < 0) goto failed;
        } else if (arg.kind == 3) {
            uint8_t flag = (uint8_t)arg.value;
            if (gak_py_append_hex(buffer, &used, &flag, 1) < 0) goto failed;
        } else {
            if (gak_py_append_u64(buffer, &used, arg.value) < 0) goto failed;
        }
    }
    if (gak_py_append(buffer, &used, "\n", 1) < 0) goto failed;
    buffer[used] = 0;
    *length = used;
    return buffer;
failed:
    free(buffer);
    gak_py_fail("Python request exceeds 1 MiB");
    return NULL;
}

#ifdef _WIN32
static wchar_t *gak_py_wide(const char *utf8) {
    int length = (int)strlen(utf8);
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, length, NULL, 0);
    if (!count) return NULL;
    wchar_t *wide = calloc((size_t)count + 1, sizeof(wchar_t));
    if (!wide) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, length, wide, count)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static wchar_t *gak_py_command(void) {
    wchar_t *runner = gak_py_wide(gak_python_runner);
    if (!runner) return NULL;
    wchar_t program[4096];
    DWORD program_length = GetModuleFileNameW(NULL, program, 4096);
    if (!program_length || program_length >= 4096) {
        free(runner);
        return NULL;
    }
    size_t exe = wcslen(gak_python_executable);
    size_t script = wcslen(runner);
    size_t capacity = (exe + script + program_length) * 2 + 32;
    wchar_t *command = calloc(capacity, sizeof(wchar_t));
    if (!command) {
        free(runner);
        return NULL;
    }
    size_t used = 0;
    const wchar_t *parts[] = {gak_python_executable, L"-I", L"-B", L"-c", runner, program};
    for (size_t part = 0; part < 6; part++) {
        if (part) command[used++] = L' ';
        command[used++] = L'"';
        const wchar_t *text = parts[part];
        for (size_t index = 0; text[index]; ) {
            size_t slashes = 0;
            while (text[index] == L'\\') { slashes++; index++; }
            if (text[index] == L'"') {
                for (size_t n = 0; n < slashes * 2 + 1; n++) command[used++] = L'\\';
                command[used++] = L'"';
                index++;
            } else {
                for (size_t n = 0; n < slashes * (text[index] ? 1 : 2); n++) command[used++] = L'\\';
                if (text[index]) command[used++] = text[index++];
            }
        }
        command[used++] = L'"';
    }
    free(runner);
    return command;
}

static void gak_py_stop(void) {
    if (!gak_py_started) return;
    TerminateProcess(gak_py_process.hProcess, 1);
    WaitForSingleObject(gak_py_process.hProcess, 1000);
    CloseHandle(gak_py_input);
    CloseHandle(gak_py_output);
    CloseHandle(gak_py_process.hThread);
    CloseHandle(gak_py_process.hProcess);
    gak_py_started = 0;
}

static int gak_py_start(void) {
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    HANDLE child_input = NULL, parent_input = NULL;
    HANDLE parent_output = NULL, child_output = NULL;
    if (!CreatePipe(&child_input, &parent_input, &inherit, 0) ||
        !CreatePipe(&parent_output, &child_output, &inherit, 0)) goto failed;
    if (!SetHandleInformation(parent_input, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(parent_output, HANDLE_FLAG_INHERIT, 0)) goto failed;
    wchar_t *command = gak_py_command();
    if (!command) goto failed;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_input;
    startup.hStdOutput = child_output;
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    memset(&gak_py_process, 0, sizeof(gak_py_process));
    BOOL started = CreateProcessW(NULL, command, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, NULL, &startup, &gak_py_process);
    free(command);
    CloseHandle(child_input);
    CloseHandle(child_output);
    if (!started) {
        CloseHandle(parent_input);
        CloseHandle(parent_output);
        gak_py_fail("cannot start Python worker");
        return -1;
    }
    gak_py_input = parent_input;
    gak_py_output = parent_output;
    gak_py_started = 1;
    atexit(gak_py_stop);
    return 0;
failed:
    if (child_input) CloseHandle(child_input);
    if (parent_input) CloseHandle(parent_input);
    if (parent_output) CloseHandle(parent_output);
    if (child_output) CloseHandle(child_output);
    gak_py_fail("cannot create Python worker pipes");
    return -1;
}

typedef struct {
    const char *request;
    size_t length;
    char *response;
    size_t used;
    int failed;
} GakPythonIo;

static DWORD WINAPI gak_py_io(void *opaque) {
    GakPythonIo *io = opaque;
    size_t sent = 0;
    while (sent < io->length) {
        DWORD count = 0;
        DWORD portion = (DWORD)((io->length - sent) > 65536 ? 65536 : io->length - sent);
        if (!WriteFile(gak_py_input, io->request + sent, portion, &count, NULL) || !count) {
            io->failed = 1;
            return 1;
        }
        sent += count;
    }
    while (io->used < GAK_PY_LIMIT) {
        DWORD count = 0;
        DWORD portion = (DWORD)((GAK_PY_LIMIT - io->used) > 4096 ? 4096 : GAK_PY_LIMIT - io->used);
        if (!ReadFile(gak_py_output, io->response + io->used, portion, &count, NULL) || !count) {
            io->failed = 1;
            return 1;
        }
        if (memchr(io->response + io->used, '\n', count)) {
            io->used += count;
            return 0;
        }
        io->used += count;
    }
    io->failed = 1;
    return 1;
}

static int gak_py_exchange(const char *request, size_t length, char *response, size_t *used) {
    GakPythonIo io = {request, length, response, 0, 0};
    HANDLE thread = CreateThread(NULL, 0, gak_py_io, &io, 0, NULL);
    if (!thread) { gak_py_fail("cannot start Python I/O"); return -1; }
    DWORD status = WaitForSingleObject(thread, GAK_PY_TIMEOUT_MS);
    if (status != WAIT_OBJECT_0) {
        gak_py_stop();
        if (WaitForSingleObject(thread, 1000) != WAIT_OBJECT_0) {
            TerminateThread(thread, 1);
            WaitForSingleObject(thread, INFINITE);
        }
        CloseHandle(thread);
        gak_py_fail("Python call timed out after 10 seconds");
        return -1;
    }
    CloseHandle(thread);
    if (io.failed) {
        gak_py_stop();
        gak_py_fail("Python worker communication failed");
        return -1;
    }
    *used = io.used;
    return 0;
}

#else
static void gak_py_stop(void) {
    if (!gak_py_started) return;
    kill(gak_py_pid, SIGKILL);
    waitpid(gak_py_pid, NULL, 0);
    close(gak_py_input);
    close(gak_py_output);
    gak_py_started = 0;
}

static int gak_py_start(void) {
    char program[4096];
    ssize_t program_length = readlink("/proc/self/exe", program, sizeof(program) - 1);
    if (program_length <= 0 || (size_t)program_length >= sizeof(program) - 1) {
        gak_py_fail("cannot locate native executable for Python imports");
        return -1;
    }
    program[program_length] = 0;
    int input[2], output[2];
    if (pipe2(input, O_CLOEXEC) != 0) {
        gak_py_fail("cannot create Python worker pipes");
        return -1;
    }
    if (pipe2(output, O_CLOEXEC) != 0) {
        close(input[0]); close(input[1]);
        gak_py_fail("cannot create Python worker pipes");
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        gak_py_fail("cannot start Python worker");
        return -1;
    }
    if (pid == 0) {
        dup2(input[0], STDIN_FILENO);
        dup2(output[1], STDOUT_FILENO);
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        char *const args[] = {gak_python_executable, "-I", "-B", "-c", (char *)gak_python_runner, program, NULL};
        execvp(gak_python_executable, args);
        _exit(127);
    }
    close(input[0]); close(output[1]);
    gak_py_input = input[1];
    gak_py_output = output[0];
    fcntl(gak_py_input, F_SETFL, fcntl(gak_py_input, F_GETFL) | O_NONBLOCK);
    fcntl(gak_py_output, F_SETFL, fcntl(gak_py_output, F_GETFL) | O_NONBLOCK);
    gak_py_pid = pid;
    gak_py_started = 1;
    atexit(gak_py_stop);
    return 0;
}

static int gak_py_wait(int fd, short events, int64_t deadline) {
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t elapsed = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
        int64_t remaining = deadline - elapsed;
        if (remaining <= 0) return 0;
        struct pollfd item = {fd, events, 0};
        int result = poll(&item, 1, (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return result;
        if (item.revents & events) return 1;
        if (item.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    }
}

static int gak_py_exchange(const char *request, size_t length, char *response, size_t *used) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + GAK_PY_TIMEOUT_MS;
    struct sigaction old, ignore = {0};
    ignore.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ignore, &old);
    size_t sent = 0;
    while (sent < length) {
        int ready = gak_py_wait(gak_py_input, POLLOUT, deadline);
        if (ready <= 0) goto failed;
        ssize_t count = write(gak_py_input, request + sent, length - sent);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) goto failed;
        sent += (size_t)count;
    }
    sigaction(SIGPIPE, &old, NULL);
    *used = 0;
    while (*used < GAK_PY_LIMIT) {
        int ready = gak_py_wait(gak_py_output, POLLIN, deadline);
        if (ready <= 0) goto failed_read;
        ssize_t count = read(gak_py_output, response + *used, GAK_PY_LIMIT - *used);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) goto failed_read;
        if (memchr(response + *used, '\n', (size_t)count)) {
            *used += (size_t)count;
            return 0;
        }
        *used += (size_t)count;
    }
failed_read:
    gak_py_stop();
    gak_py_fail("Python worker communication failed or timed out");
    return -1;
failed:
    sigaction(SIGPIPE, &old, NULL);
    goto failed_read;
}
#endif

static uint32_t gak_py_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int gak_py_list_items(const uint8_t *bytes, size_t size, uint64_t expected,
                             uint64_t *list) {
    if (size < 4) return -1;
    uint32_t count = gak_py_u32(bytes);
    if (count > 100000) return -1;
    size_t offset = 4;
    for (uint32_t index = 0; index < count; index++) {
        size_t length;
        if (expected == 6 || expected == 7) {
            length = 8;
        } else if (expected == 8) {
            length = 1;
        } else {
            if (size - offset < 4) return -1;
            length = gak_py_u32(bytes + offset);
            offset += 4;
            if (length > 500000) return -1;
        }
        if (length > size - offset) return -1;
        if (expected == 8 && bytes[offset] > 1) return -1;
        if (list) {
            if (expected == 9 || expected == 10) {
                uint8_t *box = gak_py_box((const char *)bytes + offset, length);
                if (!box) return -1;
                list[index + 1] = (uint64_t)(uintptr_t)box;
            } else {
                uint64_t value = 0;
                for (size_t byte = 0; byte < length; byte++)
                    value |= (uint64_t)bytes[offset + byte] << (byte * 8);
                list[index + 1] = value;
            }
        }
        offset += length;
    }
    return offset == size ? (int)count : -1;
}

static uint64_t *gak_py_decode_list(const uint8_t *bytes, size_t size, uint64_t expected) {
    int count = gak_py_list_items(bytes, size, expected, NULL);
    if (count < 0) {
        gak_py_fail("invalid Python worker list");
        return NULL;
    }
    size_t allocation = ((size_t)count + 1) * sizeof(uint64_t);
    if (allocation > GAK_PY_MEMORY_LIMIT - gak_py_allocated) {
        gak_py_fail("native Python result memory exceeds 64 MiB");
        return NULL;
    }
    uint64_t *list = malloc(allocation);
    if (!list) {
        gak_py_fail("native allocation failed");
        return NULL;
    }
    gak_py_allocated += allocation;
    list[0] = (uint64_t)count;
    if (gak_py_list_items(bytes, size, expected, list) < 0) {
        free(list);
        gak_py_fail("native Python result memory exceeds 64 MiB");
        return NULL;
    }
    return list;
}

static GakPythonResult *gak_py_decode(char *response, size_t size, uint64_t expected) {
    char *newline = memchr(response, '\n', size);
    if (!newline || newline != response + size - 1) {
        gak_py_fail("invalid Python worker response");
        return NULL;
    }
    *newline = 0;
    if (size >= 2 && response[0] == 'E' && response[1] == '\t') {
        size_t hex_size = size - 3;
        char *message = malloc(hex_size / 2 + 1);
        if (!message) { gak_py_fail("native allocation failed"); return NULL; }
        if (gak_py_unhex((uint8_t *)message, response + 2, hex_size) != 0) {
            free(message);
            gak_py_fail("invalid Python worker error");
            return NULL;
        }
        message[hex_size / 2] = 0;
        gak_py_fail("Python call failed: %s", message);
        free(message);
        return NULL;
    }
    if (size < 5 || response[0] != 'O' || response[1] != '\t' || response[3] != '\t') {
        gak_py_fail("invalid Python worker response");
        return NULL;
    }
    char kind = response[2];
    if (kind != gak_py_kind(expected) && !(expected == 2 && kind == 'i')) {
        gak_py_fail("Python result does not match the declared Galeikan type");
        return NULL;
    }
    size_t hex_size = size - 5;
    if (hex_size & 1 || hex_size > GAK_PY_LIMIT - 5) {
        gak_py_fail("invalid Python worker value");
        return NULL;
    }
    size_t length = hex_size / 2;
    uint8_t *bytes = malloc(length ? length : 1);
    if (!bytes) { gak_py_fail("native allocation failed"); return NULL; }
    if (gak_py_unhex(bytes, response + 4, hex_size) != 0) {
        free(bytes);
        gak_py_fail("invalid Python worker value");
        return NULL;
    }
    if (expected == 2 && kind == 'i' && (length != 8 || (bytes[7] & 0x80))) {
        free(bytes);
        gak_py_fail("Python result does not match the declared Galeikan type");
        return NULL;
    }
    if (gak_py_allocated > GAK_PY_MEMORY_LIMIT - sizeof(GakPythonResult)) {
        free(bytes);
        gak_py_fail("native Python result memory exceeds 64 MiB");
        return NULL;
    }
    GakPythonResult *result = malloc(sizeof(*result));
    if (!result) {
        free(bytes);
        gak_py_fail("native allocation failed");
        return NULL;
    }
    gak_py_allocated += sizeof(*result);
    result->kind = expected;
    if (expected >= 6) {
        uint64_t *list = gak_py_decode_list(bytes, length, expected);
        if (!list) {
            free(bytes); free(result);
            return NULL;
        }
        result->value = (uint64_t)(uintptr_t)list;
    } else if (expected == 4 || expected == 5) {
        uint8_t *box = gak_py_box((char *)bytes, length);
        if (!box) {
            free(bytes); free(result);
            gak_py_fail("native allocation failed");
            return NULL;
        }
        result->value = (uint64_t)(uintptr_t)box;
    } else {
        if ((expected == 1 || expected == 2) && length != 8) {
            free(bytes); free(result);
            gak_py_fail("invalid Python worker integer");
            return NULL;
        }
        if (expected == 3 && (length != 1 || bytes[0] > 1)) {
            free(bytes); free(result);
            gak_py_fail("invalid Python worker boolean");
            return NULL;
        }
        uint64_t value = 0;
        for (size_t index = 0; index < length; index++) value |= (uint64_t)bytes[index] << (index * 8);
        result->value = value;
    }
    free(bytes);
    return result;
}

void *gak_native_python_call(void *pointer) {
    GakPythonRequest *request = pointer;
    gak_python_error = NULL;
    if (!request || !gak_python_executable) {
        free(request);
        gak_py_fail("Python execution not allowed; pass --allow-python");
        return NULL;
    }
    size_t length = 0;
    char *encoded = gak_py_encode(request, &length);
    uint64_t expected = request->expected;
    free(request);
    if (!encoded) return NULL;
    if (!gak_py_started && gak_py_start() != 0) { free(encoded); return NULL; }
    char *response = malloc(GAK_PY_LIMIT + 1);
    if (!response) { free(encoded); gak_py_fail("native allocation failed"); return NULL; }
    size_t used = 0;
    int status = gak_py_exchange(encoded, length, response, &used);
    free(encoded);
    if (status != 0) { free(response); return NULL; }
    GakPythonResult *result = gak_py_decode(response, used, expected);
    free(response);
    return result;
}
