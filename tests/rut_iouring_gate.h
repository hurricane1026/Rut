#pragma once

#include "downstream_publication_gate.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>

#define RUT_IOURING_GATE_MAGIC UINT64_C(0x525554494F475431)
#define RUT_IOURING_GATE_VERSION UINT32_C(2)

enum rut_iouring_gate_error {
    RUT_IOURING_GATE_ERROR_NONE = 0,
    RUT_IOURING_GATE_ERROR_PROTOCOL = 1,
    RUT_IOURING_GATE_ERROR_TARGET = 2,
    RUT_IOURING_GATE_ERROR_RING = 3,
    RUT_IOURING_GATE_ERROR_SQ = 4,
    RUT_IOURING_GATE_ERROR_RECV_OWNER = 5,
    RUT_IOURING_GATE_ERROR_CQ = 6,
    RUT_IOURING_GATE_ERROR_BUFFER = 7,
    RUT_IOURING_GATE_ERROR_REQUEST_MISMATCH = 8,
    RUT_IOURING_GATE_ERROR_TIMEOUT = 9,
    RUT_IOURING_GATE_ERROR_TRANSITION = 10,
};

struct rut_iouring_gate {
    uint64_t magic;
    uint32_t version;
    uint32_t layout_size;
    uint32_t state;
    uint32_t error_code;
    uint32_t hook_magic_ok;
    uint32_t hook_version;
    uint32_t hook_layout_size;
    uint32_t target_pid;
    uint32_t target_peer_ipv4_be;
    uint16_t target_peer_port_be;
    uint16_t reserved0;
    int32_t ring_fd;
    int32_t intercepted_fd;
    uint32_t ring_ready;
    uint32_t intercepted_opcode;
    uint32_t intercepted_length;
    uint32_t intercepted_prefix_length;
    uint64_t intercepted_user_data;
    uint64_t recv_user_data;
    uint32_t sq_head_at_hit;
    uint32_t sq_tail_at_hit;
    uint32_t cq_head_at_hit;
    uint32_t cq_tail_at_arrival;
    uint32_t witness_fragments;
    uint32_t witness_length;
    uint32_t request_two_length;
    uint32_t identity_mutex_initialized;
    pthread_mutex_t identity_mutex;
    unsigned char intercepted_prefix[RUT_DOWNSTREAM_GATE_PREFIX_CAPACITY];
    unsigned char request_two[RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY];
};

static inline void rut_iouring_gate_recover_owner_death_locked(struct rut_iouring_gate* gate) {
    uint32_t expected = RUT_IOURING_GATE_ERROR_NONE;
    (void)__atomic_compare_exchange_n(&gate->error_code,
                                      &expected,
                                      RUT_IOURING_GATE_ERROR_TRANSITION,
                                      0,
                                      __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE);
    gate->ring_fd = -1;
    gate->intercepted_fd = -1;
    gate->intercepted_opcode = 0;
    gate->intercepted_length = 0;
    gate->intercepted_prefix_length = 0;
    gate->intercepted_user_data = 0;
    gate->recv_user_data = 0;
    gate->sq_head_at_hit = 0;
    gate->sq_tail_at_hit = 0;
    gate->cq_head_at_hit = 0;
    gate->cq_tail_at_arrival = 0;
    gate->witness_fragments = 0;
    gate->witness_length = 0;
    memset(gate->intercepted_prefix, 0, sizeof(gate->intercepted_prefix));
    rut_downstream_gate_store(&gate->ring_ready, 0);
    rut_downstream_gate_store(&gate->state, RUT_DOWNSTREAM_GATE_FAILED);
}

static inline int rut_iouring_gate_lock_identity(struct rut_iouring_gate* gate, int timeout_ms) {
    if (rut_downstream_gate_load(&gate->identity_mutex_initialized) != 1 || timeout_ms <= 0)
        return 0;
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return 0;
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    const int result = pthread_mutex_timedlock(&gate->identity_mutex, &deadline);
    if (result == 0) return 1;
    if (result != EOWNERDEAD) return 0;
    rut_iouring_gate_recover_owner_death_locked(gate);
    if (pthread_mutex_consistent(&gate->identity_mutex) != 0) {
        (void)pthread_mutex_unlock(&gate->identity_mutex);
        return 0;
    }
    rut_downstream_gate_wake(&gate->state);
    return 1;
}

static inline void rut_iouring_gate_unlock_identity(struct rut_iouring_gate* gate) {
    (void)pthread_mutex_unlock(&gate->identity_mutex);
}

static inline int rut_iouring_gate_wait_until(struct rut_iouring_gate* gate,
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

#if defined(__cplusplus) && defined(__x86_64__)
static_assert(sizeof(struct rut_iouring_gate) == 704);
#elif defined(__x86_64__)
_Static_assert(sizeof(struct rut_iouring_gate) == 704, "RUT io_uring gate layout drift");
#endif
