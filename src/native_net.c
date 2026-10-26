#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET GakSocket;
#define GAK_BAD_SOCKET INVALID_SOCKET
static void gak_net_cleanup(void) { WSACleanup(); }
static int gak_winsock_started;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef int GakSocket;
#define GAK_BAD_SOCKET (-1)
#endif

#define GAK_NET_REQUEST_LIMIT 1048576u
#define GAK_NET_RESPONSE_LIMIT 16777216u
#define GAK_NET_READ_CHUNK 8192u
#define GAK_NET_MAX_ADDRESSES 32u
#define GAK_NET_MAX_PENDING_DNS 8u

#ifdef _WIN32
#define GAK_NET_SEND_FLAGS 0
#else
#define GAK_NET_SEND_FLAGS MSG_NOSIGNAL
#endif

typedef struct {
    uint8_t *backing;
    uint8_t *label;
    uint8_t *origin;
} GakNetSource;

typedef struct {
    struct sockaddr_storage address;
    socklen_t length;
    int family;
} GakNetAddress;

typedef struct {
    char host[256];
    char service[6];
    int datagram;
    GakNetAddress addresses[GAK_NET_MAX_ADDRESSES];
    size_t count;
    int resolve_error;
    char error_text[256];
#ifdef _WIN32
    HANDLE finished;
    volatile LONG references;
#else
    pthread_mutex_t mutex;
    pthread_cond_t finished;
    _Atomic unsigned references;
    int done;
#endif
} GakDnsTask;

#ifdef _WIN32
static volatile LONG gak_pending_dns;
#else
static _Atomic unsigned gak_pending_dns;
#endif

extern uint8_t *gak_file_error;
extern int gak_native_net_allowed(const char *authority);
extern uint8_t *gak_native_metadata_box(const char *text, size_t length);

static void gak_net_fail(const char *format, ...) {
    char message[4096];
    va_list arguments;
    va_start(arguments, format);
    int size = vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    if (size < 0) size = 0;
    if ((size_t)size >= sizeof(message)) size = (int)sizeof(message) - 1;
    gak_file_error = gak_native_metadata_box(message, (size_t)size);
    if (!gak_file_error) {
        static const struct { uint64_t length; char message[25]; } oom =
            {24, "native allocation failed"};
        gak_file_error = (uint8_t *)&oom;
    }
}

static uint64_t gak_net_length(const uint8_t *box) {
    uint64_t size;
    memcpy(&size, box, 8);
    return size;
}

static uint64_t gak_now_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

static void gak_close_socket(GakSocket socket) {
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

static GakSocket gak_open_socket(int family) {
    return socket(family, SOCK_STREAM, IPPROTO_TCP);
}

static GakSocket gak_open_datagram_socket(int family) {
    return socket(family, SOCK_DGRAM, IPPROTO_UDP);
}

static int gak_nonblocking(GakSocket socket) {
#ifdef _WIN32
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0;
#else
    int flags = fcntl(socket, F_GETFL);
    return flags >= 0 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static int gak_would_block(void) {
#ifdef _WIN32
    int error = WSAGetLastError();
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
    return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS;
#endif
}

static int gak_wait_socket(GakSocket socket, int writable, uint64_t deadline) {
    for (;;) {
        uint64_t now = gak_now_ms();
        if (now >= deadline) return 0;
        uint64_t remaining = deadline - now;
#ifdef _WIN32
        fd_set set, exceptions;
        FD_ZERO(&set);
        FD_SET(socket, &set);
        FD_ZERO(&exceptions);
        if (writable) FD_SET(socket, &exceptions);
        struct timeval timeout = {(long)(remaining / 1000), (long)((remaining % 1000) * 1000)};
        int ready = select(0, writable ? NULL : &set, writable ? &set : NULL,
                           writable ? &exceptions : NULL, &timeout);
        if (ready < 0 && WSAGetLastError() == WSAEINTR) continue;
#else
        struct pollfd item = {socket, writable ? POLLOUT : POLLIN, 0};
        int ready = poll(&item, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready > 0 && (item.revents & (POLLERR | POLLNVAL)) &&
            !(item.revents & (writable ? POLLOUT : POLLIN))) return -1;
#endif
        return ready > 0 ? 1 : ready;
    }
}

static int gak_socket_connect(GakSocket socket, const struct sockaddr *address,
                              socklen_t length, uint64_t deadline) {
    if (connect(socket, address, length) == 0) return 0;
    if (!gak_would_block()) return -1;
    int ready = gak_wait_socket(socket, 1, deadline);
    if (ready <= 0) return ready == 0 ? 1 : -1;
    int error = 0;
#ifdef _WIN32
    int size = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&error, &size) != 0) return -1;
#else
    socklen_t size = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &size) != 0) return -1;
#endif
    return error == 0 ? 0 : -1;
}

static int gak_dns_acquire_slot(void) {
#ifdef _WIN32
    LONG pending = gak_pending_dns;
    for (;;) {
        if (pending >= (LONG)GAK_NET_MAX_PENDING_DNS) return 0;
        LONG previous = InterlockedCompareExchange(&gak_pending_dns, pending + 1, pending);
        if (previous == pending) return 1;
        pending = previous;
    }
#else
    unsigned pending = atomic_load_explicit(&gak_pending_dns, memory_order_relaxed);
    for (;;) {
        if (pending >= GAK_NET_MAX_PENDING_DNS) return 0;
        if (atomic_compare_exchange_weak_explicit(&gak_pending_dns, &pending, pending + 1,
                                                  memory_order_acq_rel, memory_order_relaxed))
            return 1;
    }
#endif
}

static void gak_dns_release_slot(void) {
#ifdef _WIN32
    InterlockedDecrement(&gak_pending_dns);
#else
    atomic_fetch_sub_explicit(&gak_pending_dns, 1, memory_order_acq_rel);
#endif
}

static void gak_dns_release_task(GakDnsTask *task) {
#ifdef _WIN32
    if (InterlockedDecrement(&task->references) != 0) return;
    CloseHandle(task->finished);
#else
    if (atomic_fetch_sub_explicit(&task->references, 1, memory_order_acq_rel) != 1) return;
    pthread_cond_destroy(&task->finished);
    pthread_mutex_destroy(&task->mutex);
#endif
    free(task);
}

static void gak_dns_run(GakDnsTask *task) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = task->datagram ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = task->datagram ? IPPROTO_UDP : IPPROTO_TCP;
    struct addrinfo *resolved = NULL;
    int error = getaddrinfo(task->host, task->service, &hints, &resolved);
    if (error) {
        task->resolve_error = 1;
#ifdef _WIN32
        const char *detail = gai_strerrorA(error);
#else
        const char *detail = gai_strerror(error);
#endif
        snprintf(task->error_text, sizeof(task->error_text), "%s",
                 detail ? detail : "unknown DNS error");
    } else {
        for (const struct addrinfo *item = resolved;
             item && task->count < GAK_NET_MAX_ADDRESSES; item = item->ai_next) {
            if ((item->ai_family != AF_INET && item->ai_family != AF_INET6) ||
                !item->ai_addr || item->ai_addrlen > sizeof(struct sockaddr_storage))
                continue;
            GakNetAddress *target = &task->addresses[task->count++];
            memcpy(&target->address, item->ai_addr, item->ai_addrlen);
            target->length = (socklen_t)item->ai_addrlen;
            target->family = item->ai_family;
        }
        freeaddrinfo(resolved);
    }
#ifdef _WIN32
    gak_dns_release_slot();
    SetEvent(task->finished);
#else
    pthread_mutex_lock(&task->mutex);
    task->done = 1;
    pthread_cond_signal(&task->finished);
    pthread_mutex_unlock(&task->mutex);
    gak_dns_release_slot();
#endif
    gak_dns_release_task(task);
}

#ifdef _WIN32
static DWORD WINAPI gak_dns_worker(void *argument) {
    gak_dns_run((GakDnsTask *)argument);
    return 0;
}
#else
static void *gak_dns_worker(void *argument) {
    gak_dns_run((GakDnsTask *)argument);
    return NULL;
}
#endif

/* The worker owns one reference after creation; a timed-out caller can safely leave it running. */
static int gak_dns_resolve(const char *host, uint16_t port, const char *authority,
                           int datagram,
                           uint64_t deadline, GakNetAddress *addresses, size_t *count) {
    if (gak_now_ms() >= deadline) return 1;
    if (!gak_dns_acquire_slot()) {
        gak_net_fail("too many pending DNS lookups");
        return -1;
    }
    GakDnsTask *task = calloc(1, sizeof(*task));
    if (!task) {
        gak_dns_release_slot();
        gak_net_fail("native allocation failed");
        return -1;
    }
    memcpy(task->host, host, strlen(host) + 1);
    snprintf(task->service, sizeof(task->service), "%u", (unsigned)port);
    task->datagram = datagram;
#ifdef _WIN32
    task->references = 2;
    task->finished = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!task->finished) {
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    HANDLE worker = CreateThread(NULL, 0, gak_dns_worker, task, 0, NULL);
    if (!worker) {
        CloseHandle(task->finished);
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    CloseHandle(worker);
    DWORD wait_result = WAIT_TIMEOUT;
    for (;;) {
        uint64_t now = gak_now_ms();
        if (now >= deadline) break;
        uint64_t remaining = deadline - now;
        wait_result = WaitForSingleObject(task->finished, (DWORD)remaining);
        if (wait_result != WAIT_TIMEOUT) break;
    }
    int completed = wait_result == WAIT_OBJECT_0 && gak_now_ms() < deadline;
    int wait_failed = wait_result == WAIT_FAILED;
#else
    atomic_init(&task->references, 2);
    if (pthread_mutex_init(&task->mutex, NULL) != 0) {
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    pthread_condattr_t attributes;
    int initialized = pthread_condattr_init(&attributes) == 0;
    int configured = initialized && pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0;
    int ready = configured && pthread_cond_init(&task->finished, &attributes) == 0;
    if (initialized) pthread_condattr_destroy(&attributes);
    if (!ready) {
        pthread_mutex_destroy(&task->mutex);
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    pthread_attr_t worker_attributes;
    int worker_attributes_ready = pthread_attr_init(&worker_attributes) == 0;
    int worker_detached = worker_attributes_ready &&
        pthread_attr_setdetachstate(&worker_attributes, PTHREAD_CREATE_DETACHED) == 0;
    if (!worker_detached) {
        if (worker_attributes_ready) pthread_attr_destroy(&worker_attributes);
        pthread_cond_destroy(&task->finished);
        pthread_mutex_destroy(&task->mutex);
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    pthread_t worker;
    int spawn_error = pthread_create(&worker, &worker_attributes, gak_dns_worker, task);
    pthread_attr_destroy(&worker_attributes);
    if (spawn_error != 0) {
        pthread_cond_destroy(&task->finished);
        pthread_mutex_destroy(&task->mutex);
        free(task);
        gak_dns_release_slot();
        gak_net_fail("cannot start DNS lookup");
        return -1;
    }
    struct timespec end = {(time_t)(deadline / 1000),
                           (long)((deadline % 1000) * 1000000)};
    pthread_mutex_lock(&task->mutex);
    int wait_failed = 0;
    while (!task->done && gak_now_ms() < deadline) {
        int wait_status = pthread_cond_timedwait(&task->finished, &task->mutex, &end);
        if (wait_status == ETIMEDOUT) break;
        if (wait_status != 0) {
            wait_failed = 1;
            break;
        }
    }
    int completed = task->done && gak_now_ms() < deadline;
    pthread_mutex_unlock(&task->mutex);
#endif
    int result = 0;
    if (wait_failed) {
        gak_net_fail("DNS lookup worker failed");
        result = -1;
    } else if (!completed) {
        result = 1;
    } else if (task->resolve_error) {
        gak_net_fail("cannot resolve %s: %s", authority, task->error_text);
        result = -1;
    } else {
        *count = task->count;
        memcpy(addresses, task->addresses, task->count * sizeof(*addresses));
    }
    gak_dns_release_task(task);
    return result;
}

static int gak_net_peer(GakSocket socket, char *text, size_t text_size) {
    struct sockaddr_storage address;
    socklen_t address_size = sizeof(address);
    if (getpeername(socket, (struct sockaddr *)&address, &address_size) != 0) return 0;
    char numeric[INET6_ADDRSTRLEN];
    if (address.ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
#ifdef _WIN32
        if (!InetNtopA(AF_INET, &ipv4->sin_addr, numeric, sizeof(numeric))) return 0;
#else
        if (!inet_ntop(AF_INET, &ipv4->sin_addr, numeric, sizeof(numeric))) return 0;
#endif
        snprintf(text, text_size, "%s:%u", numeric, (unsigned)ntohs(ipv4->sin_port));
        return 1;
    }
    if (address.ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
#ifdef _WIN32
        if (!InetNtopA(AF_INET6, &ipv6->sin6_addr, numeric, sizeof(numeric))) return 0;
#else
        if (!inet_ntop(AF_INET6, &ipv6->sin6_addr, numeric, sizeof(numeric))) return 0;
#endif
        if (ipv6->sin6_scope_id)
            snprintf(text, text_size, "[%s%%%u]:%u", numeric,
                     (unsigned)ipv6->sin6_scope_id, (unsigned)ntohs(ipv6->sin6_port));
        else
            snprintf(text, text_size, "[%s]:%u", numeric, (unsigned)ntohs(ipv6->sin6_port));
        return 1;
    }
    return 0;
}

static GakNetSource *gak_net_source(uint8_t *backing, size_t received,
                                    const char *scheme, const char *authority,
                                    const char *peer) {
    uint64_t size = (uint64_t)received;
    memcpy(backing, &size, 8);
    backing[received + 8] = 0;
    char label[336];
    char origin[704];
    snprintf(label, sizeof(label), "%s://%s", scheme, authority);
    snprintf(origin, sizeof(origin), "%s (peer %s)", label, peer);
    GakNetSource *result = malloc(sizeof(*result));
    if (!result) {
        free(backing);
        gak_net_fail("native allocation failed");
        return NULL;
    }
    result->backing = backing;
    result->label = gak_native_metadata_box(label, strlen(label));
    result->origin = gak_native_metadata_box(origin, strlen(origin));
    if (!result->label || !result->origin) {
        free(result->label);
        free(result->origin);
        free(result);
        free(backing);
        gak_net_fail("native allocation failed");
        return NULL;
    }
    return result;
}

GakNetSource *gak_native_net_exchange(const uint8_t *host_box, int64_t port,
                                      const uint8_t *request_box, int64_t max_bytes,
                                      int64_t timeout_ms) {
    gak_file_error = NULL;
    if (!host_box || gak_net_length(host_box) < 1 || gak_net_length(host_box) > 255) {
        gak_net_fail("host must contain 1 to 255 bytes");
        return NULL;
    }
    size_t host_length = (size_t)gak_net_length(host_box);
    if (memchr(host_box + 8, 0, host_length)) {
        gak_net_fail("host contains NUL");
        return NULL;
    }
    char host[256];
    memcpy(host, host_box + 8, host_length);
    host[host_length] = 0;
    if (port < 1 || port > 65535) {
        gak_net_fail("port out of range");
        return NULL;
    }
#ifdef _WIN32
    WSADATA winsock;
    if (!gak_winsock_started) {
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
            gak_net_fail("TCP socket setup failed");
            return NULL;
        }
        gak_winsock_started = 1;
        atexit(gak_net_cleanup);
    }
#endif
    struct in_addr ipv4;
    struct in6_addr ipv6;
#ifdef _WIN32
    int is_ipv4 = InetPtonA(AF_INET, host, &ipv4) == 1;
    int is_ipv6 = InetPtonA(AF_INET6, host, &ipv6) == 1;
#else
    int is_ipv4 = inet_pton(AF_INET, host, &ipv4) == 1;
    int is_ipv6 = inet_pton(AF_INET6, host, &ipv6) == 1;
#endif
    char authority[320];
    if (is_ipv6)
        snprintf(authority, sizeof(authority), "[%s]:%lld", host, (long long)port);
    else
        snprintf(authority, sizeof(authority), "%s:%lld", host, (long long)port);
    if (!gak_native_net_allowed(authority)) {
        gak_net_fail("network access not allowed: %s", authority);
        return NULL;
    }
    uint64_t request_length = gak_net_length(request_box);
    if (request_length > GAK_NET_REQUEST_LIMIT) {
        gak_net_fail("request exceeds 1048576 bytes");
        return NULL;
    }
    if (max_bytes < 0) {
        gak_net_fail("max_bytes out of range");
        return NULL;
    }
    if (max_bytes > GAK_NET_RESPONSE_LIMIT) {
        gak_net_fail("max_bytes must be at most 16777216");
        return NULL;
    }
    if (timeout_ms < 1 || timeout_ms > 30000) {
        gak_net_fail("timeout_ms must be between 1 and 30000");
        return NULL;
    }

    uint64_t deadline = gak_now_ms() + (uint64_t)timeout_ms;
    GakNetAddress addresses[GAK_NET_MAX_ADDRESSES];
    size_t address_count = 0;
    if (is_ipv4) {
        GakNetAddress *entry = &addresses[address_count++];
        memset(entry, 0, sizeof(*entry));
        struct sockaddr_in *target = (struct sockaddr_in *)&entry->address;
        target->sin_family = AF_INET;
        target->sin_port = htons((uint16_t)port);
        target->sin_addr = ipv4;
        entry->family = AF_INET;
        entry->length = sizeof(*target);
    } else if (is_ipv6) {
        GakNetAddress *entry = &addresses[address_count++];
        memset(entry, 0, sizeof(*entry));
        struct sockaddr_in6 *target = (struct sockaddr_in6 *)&entry->address;
        target->sin6_family = AF_INET6;
        target->sin6_port = htons((uint16_t)port);
        target->sin6_addr = ipv6;
        entry->family = AF_INET6;
        entry->length = sizeof(*target);
    } else {
        int resolution = gak_dns_resolve(host, (uint16_t)port, authority, 0, deadline,
                                         addresses, &address_count);
        if (resolution != 0) {
            if (resolution == 1) gak_net_fail("TCP exchange timed out");
            return NULL;
        }
    }
    if (address_count == 0) {
        gak_net_fail("no address resolved for %s", authority);
        return NULL;
    }

    GakSocket socket = GAK_BAD_SOCKET;
    for (size_t index = 0; index < address_count; ++index) {
        if (gak_now_ms() >= deadline) {
            gak_net_fail("TCP exchange timed out");
            return NULL;
        }
        socket = gak_open_socket(addresses[index].family);
        if (socket == GAK_BAD_SOCKET) continue;
        if (!gak_nonblocking(socket)) {
            gak_close_socket(socket);
            socket = GAK_BAD_SOCKET;
            continue;
        }
        int connected = gak_socket_connect(socket,
                                        (const struct sockaddr *)&addresses[index].address,
                                        addresses[index].length, deadline);
        if (connected == 0) break;
        gak_close_socket(socket);
        socket = GAK_BAD_SOCKET;
        if (connected == 1) {
            gak_net_fail("TCP exchange timed out");
            return NULL;
        }
    }
    if (socket == GAK_BAD_SOCKET) {
        gak_net_fail("TCP connect failed");
        return NULL;
    }
    char peer[128];
    if (!gak_net_peer(socket, peer, sizeof(peer))) {
        gak_close_socket(socket);
        gak_net_fail("TCP peer address unavailable");
        return NULL;
    }
    size_t sent = 0;
    while (sent < (size_t)request_length) {
        if (gak_now_ms() >= deadline) goto timed_out;
        int count = send(socket, (const char *)request_box + 8 + sent,
                         (int)((size_t)request_length - sent), GAK_NET_SEND_FLAGS);
        if (count > 0) { sent += (size_t)count; continue; }
        if (count < 0 && gak_would_block()) {
            int ready = gak_wait_socket(socket, 1, deadline);
            if (ready > 0) continue;
            if (ready == 0) goto timed_out;
        }
        gak_close_socket(socket);
        gak_net_fail(count == 0 ? "TCP connection closed while writing" : "TCP write failed");
        return NULL;
    }
    if (shutdown(socket,
#ifdef _WIN32
                 SD_SEND
#else
                 SHUT_WR
#endif
                 ) != 0) {
        gak_close_socket(socket);
        gak_net_fail("TCP write shutdown failed");
        return NULL;
    }
    size_t limit = (size_t)max_bytes + 1;
    size_t capacity = limit < GAK_NET_READ_CHUNK ? limit : GAK_NET_READ_CHUNK;
    uint8_t *backing = malloc(capacity + 9);
    if (!backing) {
        gak_close_socket(socket);
        gak_net_fail("native allocation failed");
        return NULL;
    }
    size_t received = 0;
    for (;;) {
        if (gak_now_ms() >= deadline) {
            free(backing);
            goto timed_out;
        }
        if (received == capacity) {
            size_t grown = capacity > limit / 2 ? limit : capacity * 2;
            uint8_t *larger = realloc(backing, grown + 9);
            if (!larger) {
                free(backing);
                gak_close_socket(socket);
                gak_net_fail("native allocation failed");
                return NULL;
            }
            backing = larger;
            capacity = grown;
        }
        size_t available = capacity - received;
        int count = recv(socket, (char *)backing + 8 + received,
                         (int)(available < GAK_NET_READ_CHUNK ? available : GAK_NET_READ_CHUNK), 0);
        if (count > 0) {
            received += (size_t)count;
            if (received > (size_t)max_bytes) {
                free(backing);
                gak_close_socket(socket);
                gak_net_fail("LimitExceeded: TCP response exceeds %lld bytes", (long long)max_bytes);
                return NULL;
            }
            continue;
        }
        if (count == 0) break;
        if (gak_would_block()) {
            int ready = gak_wait_socket(socket, 0, deadline);
            if (ready > 0) continue;
            if (ready == 0) { free(backing); goto timed_out; }
        }
        free(backing);
        gak_close_socket(socket);
        gak_net_fail("TCP read failed");
        return NULL;
    }
    gak_close_socket(socket);
    if (capacity != received) {
        uint8_t *smaller = realloc(backing, received + 9);
        if (!smaller) {
            smaller = malloc(received + 9);
            if (!smaller) {
                free(backing);
                gak_net_fail("native allocation failed");
                return NULL;
            }
            memcpy(smaller, backing, received + 8);
            free(backing);
        }
        backing = smaller;
    }
    return gak_net_source(backing, received, "tcp", authority, peer);

timed_out:
    gak_close_socket(socket);
    gak_net_fail("TCP exchange timed out");
    return NULL;
}

GakNetSource *gak_native_net_datagram(const uint8_t *host_box, int64_t port,
                                      const uint8_t *request_box, int64_t max_bytes,
                                      int64_t timeout_ms) {
    gak_file_error = NULL;
    if (!host_box || gak_net_length(host_box) < 1 || gak_net_length(host_box) > 255) {
        gak_net_fail("host must contain 1 to 255 bytes");
        return NULL;
    }
    size_t host_length = (size_t)gak_net_length(host_box);
    if (memchr(host_box + 8, 0, host_length)) {
        gak_net_fail("host contains NUL");
        return NULL;
    }
    char host[256];
    memcpy(host, host_box + 8, host_length);
    host[host_length] = 0;
    if (port < 1 || port > 65535) {
        gak_net_fail("port out of range");
        return NULL;
    }
#ifdef _WIN32
    WSADATA winsock;
    if (!gak_winsock_started) {
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
            gak_net_fail("UDP socket setup failed");
            return NULL;
        }
        gak_winsock_started = 1;
        atexit(gak_net_cleanup);
    }
#endif
    struct in_addr ipv4;
    struct in6_addr ipv6;
#ifdef _WIN32
    int is_ipv4 = InetPtonA(AF_INET, host, &ipv4) == 1;
    int is_ipv6 = InetPtonA(AF_INET6, host, &ipv6) == 1;
#else
    int is_ipv4 = inet_pton(AF_INET, host, &ipv4) == 1;
    int is_ipv6 = inet_pton(AF_INET6, host, &ipv6) == 1;
#endif
    char authority[320];
    if (is_ipv6)
        snprintf(authority, sizeof(authority), "[%s]:%lld", host, (long long)port);
    else
        snprintf(authority, sizeof(authority), "%s:%lld", host, (long long)port);
    if (!gak_native_net_allowed(authority)) {
        gak_net_fail("network access not allowed: %s", authority);
        return NULL;
    }
    uint64_t request_length = gak_net_length(request_box);
    if (request_length > 65507u) {
        gak_net_fail("request exceeds 65507 bytes");
        return NULL;
    }
    if (max_bytes < 0) {
        gak_net_fail("max_bytes out of range");
        return NULL;
    }
    if (max_bytes > 65507) {
        gak_net_fail("max_bytes must be at most 65507");
        return NULL;
    }
    if (timeout_ms < 1 || timeout_ms > 30000) {
        gak_net_fail("timeout_ms must be between 1 and 30000");
        return NULL;
    }

    uint64_t deadline = gak_now_ms() + (uint64_t)timeout_ms;
    GakNetAddress addresses[GAK_NET_MAX_ADDRESSES];
    size_t address_count = 0;
    if (is_ipv4) {
        GakNetAddress *entry = &addresses[address_count++];
        memset(entry, 0, sizeof(*entry));
        struct sockaddr_in *target = (struct sockaddr_in *)&entry->address;
        target->sin_family = AF_INET;
        target->sin_port = htons((uint16_t)port);
        target->sin_addr = ipv4;
        entry->family = AF_INET;
        entry->length = sizeof(*target);
    } else if (is_ipv6) {
        GakNetAddress *entry = &addresses[address_count++];
        memset(entry, 0, sizeof(*entry));
        struct sockaddr_in6 *target = (struct sockaddr_in6 *)&entry->address;
        target->sin6_family = AF_INET6;
        target->sin6_port = htons((uint16_t)port);
        target->sin6_addr = ipv6;
        entry->family = AF_INET6;
        entry->length = sizeof(*target);
    } else {
        int resolution = gak_dns_resolve(host, (uint16_t)port, authority, 1, deadline,
                                         addresses, &address_count);
        if (resolution != 0) {
            if (resolution == 1) gak_net_fail("UDP exchange timed out");
            return NULL;
        }
    }
    if (address_count == 0) {
        gak_net_fail("no address resolved for %s", authority);
        return NULL;
    }

    GakSocket socket = GAK_BAD_SOCKET;
    for (size_t index = 0; index < address_count; ++index) {
        if (gak_now_ms() >= deadline) {
            gak_net_fail("UDP exchange timed out");
            return NULL;
        }
        socket = gak_open_datagram_socket(addresses[index].family);
        if (socket == GAK_BAD_SOCKET) continue;
        if (!gak_nonblocking(socket)) {
            gak_close_socket(socket);
            socket = GAK_BAD_SOCKET;
            continue;
        }
        int connected = gak_socket_connect(socket,
                                           (const struct sockaddr *)&addresses[index].address,
                                           addresses[index].length, deadline);
        if (connected == 0) break;
        gak_close_socket(socket);
        socket = GAK_BAD_SOCKET;
        if (connected == 1) {
            gak_net_fail("UDP exchange timed out");
            return NULL;
        }
    }
    if (socket == GAK_BAD_SOCKET) {
        gak_net_fail("UDP connect failed");
        return NULL;
    }
    char peer[128];
    if (!gak_net_peer(socket, peer, sizeof(peer))) {
        gak_close_socket(socket);
        gak_net_fail("UDP peer address unavailable");
        return NULL;
    }
    for (;;) {
        if (gak_now_ms() >= deadline) goto udp_timed_out;
        int sent = send(socket, (const char *)request_box + 8,
                        (int)request_length, GAK_NET_SEND_FLAGS);
        if (sent >= 0) {
            if ((uint64_t)sent != request_length) {
                gak_close_socket(socket);
                gak_net_fail("UDP wrote only %d of %llu bytes", sent,
                             (unsigned long long)request_length);
                return NULL;
            }
            break;
        }
        if (gak_would_block()) {
            int ready = gak_wait_socket(socket, 1, deadline);
            if (ready > 0) continue;
            if (ready == 0) goto udp_timed_out;
        }
        gak_close_socket(socket);
        gak_net_fail("UDP write failed");
        return NULL;
    }
    size_t capacity = (size_t)max_bytes + 1;
    uint8_t *backing = malloc(capacity + 9);
    if (!backing) {
        gak_close_socket(socket);
        gak_net_fail("native allocation failed");
        return NULL;
    }
    for (;;) {
        if (gak_now_ms() >= deadline) {
            free(backing);
            goto udp_timed_out;
        }
        int received = recv(socket, (char *)backing + 8, (int)capacity, 0);
        if (received >= 0) {
            gak_close_socket(socket);
            if (received > max_bytes) {
                free(backing);
                gak_net_fail("LimitExceeded: UDP datagram exceeds %lld bytes",
                             (long long)max_bytes);
                return NULL;
            }
            return gak_net_source(backing, (size_t)received, "udp", authority, peer);
        }
#ifdef _WIN32
        if (WSAGetLastError() == WSAEMSGSIZE) {
            free(backing);
            gak_close_socket(socket);
            gak_net_fail("LimitExceeded: UDP datagram exceeds %lld bytes",
                         (long long)max_bytes);
            return NULL;
        }
#endif
        if (gak_would_block()) {
            int ready = gak_wait_socket(socket, 0, deadline);
            if (ready > 0) continue;
            if (ready == 0) {
                free(backing);
                goto udp_timed_out;
            }
        }
        free(backing);
        gak_close_socket(socket);
        gak_net_fail("UDP read failed");
        return NULL;
    }

udp_timed_out:
    gak_close_socket(socket);
    gak_net_fail("UDP exchange timed out");
    return NULL;
}
