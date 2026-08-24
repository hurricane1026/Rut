#define _GNU_SOURCE

#include "downstream_publication_gate.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

static struct rut_downstream_publication_gate* gate;
static __thread int gate_inside;

static ssize_t (*real_write_fn)(int, const void*, size_t);
static ssize_t (*real_writev_fn)(int, const struct iovec*, int);
static ssize_t (*real_send_fn)(int, const void*, size_t, int);
static ssize_t (*real_sendmsg_fn)(int, const struct msghdr*, int);

static void gate_resolve_symbols(void) {
    if (real_write_fn != 0 && real_writev_fn != 0 && real_send_fn != 0 && real_sendmsg_fn != 0)
        return;
    gate_inside++;
    *(void**)(&real_write_fn) = dlsym(RTLD_NEXT, "write");
    *(void**)(&real_writev_fn) = dlsym(RTLD_NEXT, "writev");
    *(void**)(&real_send_fn) = dlsym(RTLD_NEXT, "send");
    *(void**)(&real_sendmsg_fn) = dlsym(RTLD_NEXT, "sendmsg");
    gate_inside--;
}

static int gate_protocol_valid(void) {
    return gate != 0 && gate->magic == RUT_DOWNSTREAM_GATE_MAGIC &&
           gate->version == RUT_DOWNSTREAM_GATE_VERSION && gate->layout_size == sizeof(*gate);
}

static int gate_is_target_master(void) {
    const char* target = getenv("RUT_DOWNSTREAM_GATE_TARGET_EXECUTABLE");
    if (target == 0 || target[0] != '/') return 0;
    char executable[PATH_MAX + 1];
    const long length = syscall(SYS_readlink, "/proc/self/exe", executable, PATH_MAX);
    if (length <= 0 || length > PATH_MAX) return 0;
    executable[length] = '\0';
    return strcmp(executable, target) == 0;
}

__attribute__((constructor)) static void gate_initialize(void) {
    const char* path = getenv("RUT_DOWNSTREAM_GATE_CONTROL");
    if (path == 0 || path[0] != '/') return;
    const int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != (off_t)sizeof(*gate)) {
        close(fd);
        return;
    }
    void* mapping = mmap(0, sizeof(*gate), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED) return;
    gate = (struct rut_downstream_publication_gate*)mapping;
    if (!gate_protocol_valid()) {
        munmap(mapping, sizeof(*gate));
        gate = 0;
        return;
    }
    gate_resolve_symbols();
    if (real_write_fn == 0 || real_writev_fn == 0 || real_send_fn == 0 || real_sendmsg_fn == 0) {
        rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_REAL_SYMBOL);
        return;
    }
    gate->hook_version = RUT_DOWNSTREAM_GATE_VERSION;
    gate->hook_layout_size = sizeof(*gate);
    rut_downstream_gate_store(&gate->hook_magic_ok, 1);
    if (gate_is_target_master()) {
        uint32_t expected = 0;
        const uint32_t master = (uint32_t)getpid();
        if (!__atomic_compare_exchange_n(&gate->target_master_pid,
                                         &expected,
                                         master,
                                         0,
                                         __ATOMIC_RELEASE,
                                         __ATOMIC_ACQUIRE) &&
            expected != master) {
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_PROTOCOL);
            return;
        }
    }
    rut_downstream_gate_wake(&gate->state);
}

__attribute__((destructor)) static void gate_destroy(void) {
    if (gate != 0) munmap(gate, sizeof(*gate));
    gate = 0;
}

static int gate_target_peer(int fd) {
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (syscall(SYS_getpeername, fd, &peer, &peer_len) != 0 ||
        peer_len < sizeof(struct sockaddr_in) || peer.sin_family != AF_INET)
        return 0;
    return peer.sin_addr.s_addr == gate->target_peer_ipv4_be &&
           peer.sin_port == gate->target_peer_port_be;
}

static size_t gate_copy_iov_prefix(
    unsigned char* out, size_t capacity, const struct iovec* iov, size_t count, uint64_t* total) {
    size_t copied = 0;
    *total = 0;
    for (size_t i = 0; i < count; i++) {
        if (UINT64_MAX - *total < iov[i].iov_len) return 0;
        *total += iov[i].iov_len;
        const size_t available = capacity - copied;
        const size_t take = iov[i].iov_len < available ? iov[i].iov_len : available;
        if (take != 0) memcpy(out + copied, iov[i].iov_base, take);
        copied += take;
    }
    return copied;
}

static int gate_is_502_prefix(const unsigned char* prefix, size_t length) {
    static const unsigned char expected[] = "HTTP/1.1 502 ";
    return length >= sizeof(expected) - 1 && memcmp(prefix, expected, sizeof(expected) - 1) == 0;
}

static int gate_wait_for_request_two(int fd) {
    const uint32_t expected_length = gate->request_two_length;
    if (expected_length == 0 || expected_length > RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY) {
        rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_PROTOCOL);
        return 0;
    }
    const int64_t deadline = rut_downstream_gate_now_ms() + 5000;
    unsigned char peek[RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY + 1];
    for (;;) {
        const int64_t now = rut_downstream_gate_now_ms();
        if (now < 0 || now >= deadline) {
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_TIMEOUT);
            return 0;
        }
        struct pollfd poll_fd = {.fd = fd, .events = POLLIN, .revents = 0};
        const int64_t remaining = deadline - now;
        const int poll_timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
        const long ready = syscall(SYS_poll, &poll_fd, 1, poll_timeout);
        if (ready < 0) {
            if (errno == EINTR) continue;
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_PEEK);
            return 0;
        }
        if (ready == 0) {
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_TIMEOUT);
            return 0;
        }
        const long received =
            syscall(SYS_recvfrom, fd, peek, expected_length + 1, MSG_PEEK | MSG_DONTWAIT, 0, 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_PEEK);
            return 0;
        }
        if (received == 0) {
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_PEEK);
            return 0;
        }
        const size_t available = (size_t)received;
        const size_t compare = available < expected_length ? available : expected_length;
        if (memcmp(peek, gate->request_two, compare) != 0 || available > expected_length) {
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_REQUEST_MISMATCH);
            return 0;
        }
        if (available == expected_length) return 1;
    }
}

static void gate_before_publication(int fd,
                                    uint32_t operation,
                                    uint64_t length,
                                    const unsigned char* prefix,
                                    size_t prefix_length) {
    if (!gate_protocol_valid() ||
        rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_ARMED)
        return;
    if (!gate_is_502_prefix(prefix, prefix_length) || !gate_target_peer(fd)) return;

    gate->intercepted_fd = fd;
    gate->intercepted_pid = (uint32_t)getpid();
    gate->intercepted_ppid = (uint32_t)getppid();
    gate->intercepted_operation = operation;
    gate->intercepted_length = length;
    gate->intercepted_prefix_length = prefix_length < RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY
                                          ? (uint32_t)prefix_length
                                          : RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY;
    memcpy(gate->intercepted_prefix, prefix, gate->intercepted_prefix_length);
    uint32_t expected = RUT_DOWNSTREAM_GATE_ARMED;
    if (!__atomic_compare_exchange_n(&gate->state,
                                     &expected,
                                     RUT_DOWNSTREAM_GATE_HIT,
                                     0,
                                     __ATOMIC_RELEASE,
                                     __ATOMIC_ACQUIRE))
        return;
    rut_downstream_gate_wake(&gate->state);

    if (!rut_downstream_gate_wait_until(gate, RUT_DOWNSTREAM_GATE_R2_SENT, 5000)) {
        if (rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_FAILED)
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_TIMEOUT);
        return;
    }
    if (!gate_wait_for_request_two(fd)) return;
    if (!rut_downstream_gate_cas(
            &gate->state, RUT_DOWNSTREAM_GATE_R2_SENT, RUT_DOWNSTREAM_GATE_R2_ARRIVED)) {
        rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_TRANSITION);
        return;
    }
    rut_downstream_gate_wake(&gate->state);
    if (!rut_downstream_gate_wait_until(gate, RUT_DOWNSTREAM_GATE_RELEASED, 5000) &&
        rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_FAILED)
        rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_TIMEOUT);
}

ssize_t write(int fd, const void* data, size_t length) {
    if (gate_inside != 0) {
        if (gate_protocol_valid() &&
            rut_downstream_gate_load(&gate->state) == RUT_DOWNSTREAM_GATE_ARMED)
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_RECURSION);
        return syscall(SYS_write, fd, data, length);
    }
    gate_resolve_symbols();
    if (real_write_fn == 0) {
        errno = ENOSYS;
        return -1;
    }
    gate_inside++;
    gate_before_publication(
        fd, RUT_DOWNSTREAM_GATE_OP_WRITE, length, (const unsigned char*)data, length);
    gate_inside--;
    return real_write_fn(fd, data, length);
}

ssize_t writev(int fd, const struct iovec* iov, int count) {
    if (gate_inside != 0) {
        if (gate_protocol_valid() &&
            rut_downstream_gate_load(&gate->state) == RUT_DOWNSTREAM_GATE_ARMED)
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_RECURSION);
        return syscall(SYS_writev, fd, iov, count);
    }
    gate_resolve_symbols();
    if (real_writev_fn == 0) {
        errno = ENOSYS;
        return -1;
    }
    unsigned char prefix[RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY];
    uint64_t total = 0;
    size_t prefix_length = 0;
    if (count > 0)
        prefix_length = gate_copy_iov_prefix(prefix, sizeof(prefix), iov, (size_t)count, &total);
    gate_inside++;
    gate_before_publication(fd, RUT_DOWNSTREAM_GATE_OP_WRITEV, total, prefix, prefix_length);
    gate_inside--;
    return real_writev_fn(fd, iov, count);
}

ssize_t send(int fd, const void* data, size_t length, int flags) {
    if (gate_inside != 0) {
        if (gate_protocol_valid() &&
            rut_downstream_gate_load(&gate->state) == RUT_DOWNSTREAM_GATE_ARMED)
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_RECURSION);
        return syscall(SYS_sendto, fd, data, length, flags, 0, 0);
    }
    gate_resolve_symbols();
    if (real_send_fn == 0) {
        errno = ENOSYS;
        return -1;
    }
    gate_inside++;
    gate_before_publication(
        fd, RUT_DOWNSTREAM_GATE_OP_SEND, length, (const unsigned char*)data, length);
    gate_inside--;
    return real_send_fn(fd, data, length, flags);
}

ssize_t sendmsg(int fd, const struct msghdr* message, int flags) {
    if (gate_inside != 0) {
        if (gate_protocol_valid() &&
            rut_downstream_gate_load(&gate->state) == RUT_DOWNSTREAM_GATE_ARMED)
            rut_downstream_gate_fail(gate, RUT_DOWNSTREAM_GATE_ERROR_RECURSION);
        return syscall(SYS_sendmsg, fd, message, flags);
    }
    gate_resolve_symbols();
    if (real_sendmsg_fn == 0) {
        errno = ENOSYS;
        return -1;
    }
    unsigned char prefix[RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY];
    uint64_t total = 0;
    size_t prefix_length = 0;
    if (message != 0 && message->msg_iov != 0)
        prefix_length = gate_copy_iov_prefix(
            prefix, sizeof(prefix), message->msg_iov, message->msg_iovlen, &total);
    gate_inside++;
    gate_before_publication(fd, RUT_DOWNSTREAM_GATE_OP_SENDMSG, total, prefix, prefix_length);
    gate_inside--;
    return real_sendmsg_fn(fd, message, flags);
}
