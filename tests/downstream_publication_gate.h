#pragma once

#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define RUT_DOWNSTREAM_GATE_MAGIC UINT64_C(0x5255544741544531)
#define RUT_DOWNSTREAM_GATE_VERSION UINT32_C(2)
#define RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY UINT32_C(32)
#define RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY UINT32_C(512)

enum rut_downstream_gate_state {
    RUT_DOWNSTREAM_GATE_DISARMED = 0,
    RUT_DOWNSTREAM_GATE_ARMED = 1,
    RUT_DOWNSTREAM_GATE_HIT = 2,
    RUT_DOWNSTREAM_GATE_R2_SENT = 3,
    RUT_DOWNSTREAM_GATE_R2_ARRIVED = 4,
    RUT_DOWNSTREAM_GATE_RELEASED = 5,
    RUT_DOWNSTREAM_GATE_FAILED = 6,
};

enum rut_downstream_gate_operation {
    RUT_DOWNSTREAM_GATE_OP_NONE = 0,
    RUT_DOWNSTREAM_GATE_OP_WRITE = 1,
    RUT_DOWNSTREAM_GATE_OP_WRITEV = 2,
    RUT_DOWNSTREAM_GATE_OP_SEND = 3,
    RUT_DOWNSTREAM_GATE_OP_SENDMSG = 4,
};

enum rut_downstream_gate_error {
    RUT_DOWNSTREAM_GATE_ERROR_NONE = 0,
    RUT_DOWNSTREAM_GATE_ERROR_PROTOCOL = 1,
    RUT_DOWNSTREAM_GATE_ERROR_REAL_SYMBOL = 2,
    RUT_DOWNSTREAM_GATE_ERROR_RECURSION = 3,
    RUT_DOWNSTREAM_GATE_ERROR_PEER = 4,
    RUT_DOWNSTREAM_GATE_ERROR_TIMEOUT = 5,
    RUT_DOWNSTREAM_GATE_ERROR_PEEK = 6,
    RUT_DOWNSTREAM_GATE_ERROR_REQUEST_MISMATCH = 7,
    RUT_DOWNSTREAM_GATE_ERROR_TRANSITION = 8,
};

struct rut_downstream_publication_gate {
    uint64_t magic;
    uint32_t version;
    uint32_t layout_size;
    uint32_t state;
    uint32_t error_code;
    uint32_t hook_magic_ok;
    uint32_t hook_version;
    uint32_t hook_layout_size;
    uint32_t target_master_pid;
    uint32_t intercepted_pid;
    uint32_t intercepted_ppid;
    uint32_t target_peer_ipv4_be;
    uint16_t target_peer_port_be;
    uint16_t reserved0;
    int32_t intercepted_fd;
    uint32_t intercepted_operation;
    uint64_t intercepted_length;
    uint32_t intercepted_prefix_length;
    uint32_t request_two_length;
    unsigned char intercepted_prefix[RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY];
    unsigned char request_two[RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY];
};

#if defined(__cplusplus)
static_assert(sizeof(struct rut_downstream_publication_gate) == 624);
#else
_Static_assert(sizeof(struct rut_downstream_publication_gate) == 624,
               "downstream publication gate layout drift");
#endif

static inline uint32_t rut_downstream_gate_load(const uint32_t* value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static inline void rut_downstream_gate_store(uint32_t* value, uint32_t next) {
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
}

static inline int rut_downstream_gate_cas(uint32_t* value, uint32_t expected, uint32_t next) {
    return __atomic_compare_exchange_n(
        value, &expected, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void rut_downstream_gate_wake(uint32_t* state) {
    (void)syscall(SYS_futex, state, FUTEX_WAKE, INT32_MAX, 0, 0, 0);
}

static inline int64_t rut_downstream_gate_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static inline int rut_downstream_gate_wait_until(struct rut_downstream_publication_gate* gate,
                                                 uint32_t wanted,
                                                 int timeout_ms) {
    const int64_t start = rut_downstream_gate_now_ms();
    if (start < 0) return 0;
    const int64_t deadline = start + timeout_ms;
    for (;;) {
        const uint32_t current = rut_downstream_gate_load(&gate->state);
        if (current == wanted) return 1;
        if (current == RUT_DOWNSTREAM_GATE_FAILED) return 0;
        const int64_t now = rut_downstream_gate_now_ms();
        if (now < 0 || now >= deadline) return 0;
        const int64_t remaining = deadline - now;
        struct timespec timeout;
        timeout.tv_sec = remaining / 1000;
        timeout.tv_nsec = (remaining % 1000) * 1000000;
        const long rc = syscall(SYS_futex, &gate->state, FUTEX_WAIT, current, &timeout, 0, 0);
        if (rc == 0 || errno == EAGAIN || errno == EINTR) continue;
        if (errno == ETIMEDOUT) return 0;
        return 0;
    }
}

static inline void rut_downstream_gate_fail(struct rut_downstream_publication_gate* gate,
                                            uint32_t error_code) {
    uint32_t expected = RUT_DOWNSTREAM_GATE_ERROR_NONE;
    (void)__atomic_compare_exchange_n(
        &gate->error_code, &expected, error_code, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_FAILED);
    rut_downstream_gate_wake(&gate->state);
}
