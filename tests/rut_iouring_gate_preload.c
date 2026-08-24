#define _GNU_SOURCE

#include "rut_iouring_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The RUT io_uring gate syscall trampoline currently requires x86-64"
#endif

_Static_assert(__NR_io_uring_setup == 425 && __NR_io_uring_enter == 426 &&
                   __NR_io_uring_register == 427,
               "x86-64 io_uring syscall numbers changed");

/*
 * These feature-bit values are stable io_uring UAPI.  Keep private names so
 * the helper also compiles against Linux 6.8 headers, which stop at bit 13,
 * while still recognizing every feature a newer production kernel may return.
 */
#define RUT_GATE_IORING_FEAT_RECVSEND_BUNDLE (UINT32_C(1) << 14)
#define RUT_GATE_IORING_FEAT_MIN_TIMEOUT (UINT32_C(1) << 15)
#define RUT_GATE_IORING_FEAT_RW_ATTR (UINT32_C(1) << 16)
#define RUT_GATE_IORING_FEAT_NO_IOWAIT (UINT32_C(1) << 17)

#ifdef IORING_FEAT_RECVSEND_BUNDLE
_Static_assert(IORING_FEAT_RECVSEND_BUNDLE == RUT_GATE_IORING_FEAT_RECVSEND_BUNDLE,
               "IORING_FEAT_RECVSEND_BUNDLE UAPI value changed");
#endif
#ifdef IORING_FEAT_MIN_TIMEOUT
_Static_assert(IORING_FEAT_MIN_TIMEOUT == RUT_GATE_IORING_FEAT_MIN_TIMEOUT,
               "IORING_FEAT_MIN_TIMEOUT UAPI value changed");
#endif
#ifdef IORING_FEAT_RW_ATTR
_Static_assert(IORING_FEAT_RW_ATTR == RUT_GATE_IORING_FEAT_RW_ATTR,
               "IORING_FEAT_RW_ATTR UAPI value changed");
#endif
#ifdef IORING_FEAT_NO_IOWAIT
_Static_assert(IORING_FEAT_NO_IOWAIT == RUT_GATE_IORING_FEAT_NO_IOWAIT,
               "IORING_FEAT_NO_IOWAIT UAPI value changed");
#endif

/*
 * Linux 6.8 names bytes [16, 40) resv[3]; newer headers split the same stable
 * UAPI bytes into min_left plus resv[5].  Validate the wire layout using only
 * fields common to both declarations, then inspect that tail bytewise.
 */
#define RUT_GATE_PBUF_REG_RESERVED_OFFSET 16U
#define RUT_GATE_PBUF_REG_RESERVED_SIZE 24U
_Static_assert(sizeof(struct io_uring_buf_reg) == 40, "io_uring_buf_reg UAPI size changed");
_Static_assert(offsetof(struct io_uring_buf_reg, ring_addr) == 0,
               "io_uring_buf_reg ring_addr offset changed");
_Static_assert(offsetof(struct io_uring_buf_reg, ring_entries) == 8,
               "io_uring_buf_reg ring_entries offset changed");
_Static_assert(offsetof(struct io_uring_buf_reg, bgid) == 12,
               "io_uring_buf_reg bgid offset changed");
_Static_assert(offsetof(struct io_uring_buf_reg, flags) == 14,
               "io_uring_buf_reg flags offset changed");
_Static_assert(offsetof(struct io_uring_buf_reg, flags) +
                       sizeof(((struct io_uring_buf_reg*)0)->flags) ==
                   RUT_GATE_PBUF_REG_RESERVED_OFFSET,
               "io_uring_buf_reg common prefix size changed");
_Static_assert(RUT_GATE_PBUF_REG_RESERVED_OFFSET + RUT_GATE_PBUF_REG_RESERVED_SIZE ==
                   sizeof(struct io_uring_buf_reg),
               "io_uring_buf_reg reserved tail is out of bounds");

#define RUT_GATE_BUFFER_COUNT 2048U
#define RUT_GATE_BUFFER_SIZE 4096U
#define RUT_GATE_BUFFER_GROUP 0U
#define RUT_GATE_RECV_EVENT 1U
#define RUT_GATE_SEND_EVENT 2U
#define RUT_GATE_UPSTREAM_CONNECT_EVENT 3U
#define RUT_GATE_TIMEOUT_EVENT 6U
#define RUT_GATE_TIMER_CONN_ID 0x00FFFFFEU
#define RUT_GATE_RING_ENTRIES 16384U
#define RUT_GATE_CQ_ENTRIES (RUT_GATE_RING_ENTRIES * 2U)
#define RUT_GATE_PBUF_RING_SIZE \
    (sizeof(struct io_uring_buf_ring) + RUT_GATE_BUFFER_COUNT * sizeof(struct io_uring_buf))
#define RUT_GATE_PBUF_DATA_SIZE ((size_t)RUT_GATE_BUFFER_COUNT * RUT_GATE_BUFFER_SIZE)

struct ring_view {
    int fd;
    struct io_uring_params params;
    void* sq_ring;
    size_t sq_ring_length;
    void* cq_ring;
    size_t cq_ring_length;
    struct io_uring_sqe* sqes;
    size_t sqes_length;
    void* buffer_data_mapping;
    size_t buffer_data_length;
    void* buffer_ring_mapping;
    size_t buffer_ring_length;
    struct io_uring_buf_ring* buffer_ring;
    uint32_t buffer_entries;
    uint16_t buffer_group;
    uint64_t target_recv_user_data;
    int setup_valid;
    int pbuf_registered;
};

static struct rut_iouring_gate* gate;
static struct ring_view ring_view = {.fd = -1};
static int target_process;
static int duplicate_sq_mapping_injected;
static int ready_mask_mutation_injected;
static int duplicate_connect_journal_injected;

/*
 * Both entry points use the x86-64 SysV variadic syscall ABI.  Define them as
 * file-scope assembly rather than naked C functions: GCC may still emit its
 * variadic register-save sequence around extended asm at -O0, and a naked
 * function has no frame for those compiler-generated stores.  The public
 * syscall symbol either tail-calls the C inspector for the three io_uring
 * calls or forwards all six kernel argument slots directly.  No va_list is
 * formed and unrelated syscall arities are never guessed.
 */
__attribute__((visibility("hidden"))) long rut_gate_kernel_syscall(long number,
                                                                   unsigned long arg1,
                                                                   unsigned long arg2,
                                                                   unsigned long arg3,
                                                                   unsigned long arg4,
                                                                   unsigned long arg5,
                                                                   unsigned long arg6);

__attribute__((visibility("hidden"))) long rut_gate_io_uring_syscall(long number,
                                                                     unsigned long arg1,
                                                                     unsigned long arg2,
                                                                     unsigned long arg3,
                                                                     unsigned long arg4,
                                                                     unsigned long arg5,
                                                                     unsigned long arg6);

__asm__(
    ".text\n"
    ".hidden rut_gate_kernel_syscall\n"
    ".type rut_gate_kernel_syscall,@function\n"
    "rut_gate_kernel_syscall:\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "mov %r8, %r10\n"
    "mov %r9, %r8\n"
    "mov 8(%rsp), %r9\n"
    "syscall\n"
    "ret\n"
    ".size rut_gate_kernel_syscall,.-rut_gate_kernel_syscall\n"
    ".globl syscall\n"
    ".type syscall,@function\n"
    "syscall:\n"
    "cmp $425, %rdi\n"
    "je rut_gate_io_uring_syscall\n"
    "cmp $426, %rdi\n"
    "je rut_gate_io_uring_syscall\n"
    "cmp $427, %rdi\n"
    "je rut_gate_io_uring_syscall\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "mov %r8, %r10\n"
    "mov %r9, %r8\n"
    "mov 8(%rsp), %r9\n"
    "syscall\n"
    "cmp $-4095, %rax\n"
    "jae 1f\n"
    "ret\n"
    "1:\n"
    "push %rax\n"
    "call __errno_location@PLT\n"
    "pop %rcx\n"
    "neg %ecx\n"
    "mov %ecx, (%rax)\n"
    "mov $-1, %rax\n"
    "ret\n"
    ".size syscall,.-syscall\n");

static long libc_result(long result) {
    if ((unsigned long)result >= (unsigned long)-4095) {
        errno = (int)-result;
        return -1;
    }
    return result;
}

static int protocol_valid(void) {
    return gate != 0 && gate->magic == RUT_IOURING_GATE_MAGIC &&
           gate->version == RUT_IOURING_GATE_VERSION && gate->layout_size == sizeof(*gate) &&
           rut_downstream_gate_load(&gate->identity_mutex_initialized) == 1;
}

static void lock_identity(void) {
    if (!rut_iouring_gate_lock_identity(gate, 2000))
        (void)rut_gate_kernel_syscall(SYS_exit_group, 125, 0, 0, 0, 0, 0);
}

static void unlock_identity(void) {
    rut_iouring_gate_unlock_identity(gate);
}

static int failed_locked(void) {
    return rut_downstream_gate_load(&gate->state) == RUT_DOWNSTREAM_GATE_FAILED;
}

static void fail_locked(uint32_t error) {
    uint32_t expected = RUT_IOURING_GATE_ERROR_NONE;
    (void)__atomic_compare_exchange_n(
        &gate->error_code, &expected, error, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
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

static void fail(uint32_t error) {
    if (!protocol_valid()) return;
    lock_identity();
    fail_locked(error);
    unlock_identity();
    rut_downstream_gate_wake(&gate->state);
}

static int exact_target_executable(void) {
    const char* target = getenv("RUT_IOURING_GATE_TARGET_EXECUTABLE");
    if (target == 0 || target[0] != '/') return 0;
    char executable[PATH_MAX + 1];
    const long length = rut_gate_kernel_syscall(SYS_readlink,
                                                (unsigned long)"/proc/self/exe",
                                                (unsigned long)executable,
                                                PATH_MAX,
                                                0,
                                                0,
                                                0);
    if (length <= 0 || length > PATH_MAX) return 0;
    executable[length] = '\0';
    return strcmp(executable, target) == 0;
}

__attribute__((constructor)) static void initialize(void) {
    const char* path = getenv("RUT_IOURING_GATE_CONTROL");
    if (path == 0 || path[0] != '/') return;
    const int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != (off_t)sizeof(*gate)) {
        close(fd);
        return;
    }
    const long mapped = rut_gate_kernel_syscall(
        SYS_mmap, 0, sizeof(*gate), PROT_READ | PROT_WRITE, MAP_SHARED, (unsigned long)fd, 0);
    close(fd);
    if ((unsigned long)mapped >= (unsigned long)-4095) return;
    gate = (struct rut_iouring_gate*)mapped;
    if (!protocol_valid()) {
        (void)rut_gate_kernel_syscall(SYS_munmap, (unsigned long)gate, sizeof(*gate), 0, 0, 0, 0);
        gate = 0;
        return;
    }
    target_process = exact_target_executable();
    if (!target_process) {
        fail(RUT_IOURING_GATE_ERROR_TARGET);
        return;
    }
    gate->target_pid = (uint32_t)getpid();
    gate->hook_version = RUT_IOURING_GATE_VERSION;
    gate->hook_layout_size = sizeof(*gate);
    rut_downstream_gate_store(&gate->hook_magic_ok, 1);
    rut_downstream_gate_wake(&gate->state);
}

__attribute__((destructor)) static void destroy(void) {
    if (gate != 0)
        (void)rut_gate_kernel_syscall(SYS_munmap, (unsigned long)gate, sizeof(*gate), 0, 0, 0, 0);
    gate = 0;
}

static int target_peer(int fd) {
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    const long result = rut_gate_kernel_syscall(
        SYS_getpeername, (unsigned long)fd, (unsigned long)&peer, (unsigned long)&length, 0, 0, 0);
    return result == 0 && length >= sizeof(peer) && peer.sin_family == AF_INET &&
           peer.sin_addr.s_addr == gate->target_peer_ipv4_be &&
           peer.sin_port == gate->target_peer_port_be;
}

static int target_upstream_connect(const struct io_uring_sqe* sqe, struct sockaddr_in* address) {
    if (sqe->opcode != IORING_OP_CONNECT) return 0;
    if (sqe->addr == 0 || sqe->off != sizeof(*address)) {
        fail(RUT_IOURING_GATE_ERROR_CONNECT_JOURNAL);
        return -1;
    }
    memcpy(address, (const void*)(uintptr_t)sqe->addr, sizeof(*address));
    if (address->sin_family != AF_INET ||
        address->sin_addr.s_addr != gate->target_upstream_ipv4_be ||
        address->sin_port != gate->target_upstream_port_be)
        return 0;
    if (sqe->flags != 0 || sqe->ioprio != 0 || sqe->len != 0 ||
        (sqe->user_data & 0xffU) != RUT_GATE_UPSTREAM_CONNECT_EVENT ||
        ((sqe->user_data >> 32) & 0xffffffU) == 0) {
        fail(RUT_IOURING_GATE_ERROR_CONNECT_JOURNAL);
        return -1;
    }
    return 1;
}

static int append_connect_attempt_locked(const struct io_uring_sqe* sqe,
                                         const struct sockaddr_in* address) {
    for (uint32_t i = 0; i < gate->connect_attempt_count; i++) {
        if (gate->connect_attempts[i].user_data == sqe->user_data) {
            gate->connect_journal_duplicate = 1;
            fail_locked(RUT_IOURING_GATE_ERROR_CONNECT_JOURNAL);
            return 0;
        }
    }
    if (gate->connect_attempt_count >= RUT_IOURING_GATE_CONNECT_JOURNAL_CAPACITY) {
        gate->connect_journal_overflow = 1;
        fail_locked(RUT_IOURING_GATE_ERROR_CONNECT_JOURNAL);
        return 0;
    }
    struct rut_iouring_gate_connect_attempt* attempt =
        &gate->connect_attempts[gate->connect_attempt_count++];
    attempt->fd = sqe->fd;
    attempt->ipv4_be = address->sin_addr.s_addr;
    attempt->port_be = address->sin_port;
    attempt->address_length = (uint16_t)sqe->off;
    attempt->user_data = sqe->user_data;
    return 1;
}

static int setup_params_valid(const struct io_uring_params* params) {
    const uint32_t known_features =
        IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | IORING_FEAT_SUBMIT_STABLE |
        IORING_FEAT_RW_CUR_POS | IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
        IORING_FEAT_POLL_32BITS | IORING_FEAT_SQPOLL_NONFIXED | IORING_FEAT_EXT_ARG |
        IORING_FEAT_NATIVE_WORKERS | IORING_FEAT_RSRC_TAGS | IORING_FEAT_CQE_SKIP |
        IORING_FEAT_LINKED_FILE | IORING_FEAT_REG_REG_RING | RUT_GATE_IORING_FEAT_RECVSEND_BUNDLE |
        RUT_GATE_IORING_FEAT_MIN_TIMEOUT | RUT_GATE_IORING_FEAT_RW_ATTR |
        RUT_GATE_IORING_FEAT_NO_IOWAIT;
    const uint32_t required_features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP;
    if (params == 0 || params->sq_entries != RUT_GATE_RING_ENTRIES ||
        params->cq_entries != RUT_GATE_CQ_ENTRIES || params->flags != IORING_SETUP_COOP_TASKRUN ||
        params->sq_thread_cpu != 0 || params->sq_thread_idle != 0 || params->wq_fd != 0 ||
        params->resv[0] != 0 || params->resv[1] != 0 || params->resv[2] != 0 ||
        (params->features & required_features) != required_features ||
        (params->features & ~known_features) != 0)
        return 0;

    const uint64_t cq_size =
        (uint64_t)params->cq_off.cqes + (uint64_t)params->cq_entries * sizeof(struct io_uring_cqe);
    const uint64_t sq_size =
        (uint64_t)params->sq_off.array + (uint64_t)params->sq_entries * sizeof(uint32_t);
    if (cq_size > SIZE_MAX || sq_size > SIZE_MAX || params->sq_off.head != 0 ||
        params->sq_off.tail != sizeof(uint32_t) ||
        params->sq_off.ring_mask != 4U * sizeof(uint32_t) ||
        params->sq_off.ring_entries != 6U * sizeof(uint32_t) ||
        params->sq_off.dropped != 8U * sizeof(uint32_t) ||
        params->sq_off.flags != 9U * sizeof(uint32_t) || params->sq_off.array != cq_size ||
        params->sq_off.resv1 != 0 || params->sq_off.user_addr != 0 ||
        params->cq_off.head != 2U * sizeof(uint32_t) ||
        params->cq_off.tail != 3U * sizeof(uint32_t) ||
        params->cq_off.ring_mask != 5U * sizeof(uint32_t) ||
        params->cq_off.ring_entries != 7U * sizeof(uint32_t) ||
        params->cq_off.flags != 10U * sizeof(uint32_t) ||
        params->cq_off.overflow != 11U * sizeof(uint32_t) || params->cq_off.cqes != 64U ||
        params->cq_off.resv1 != 0 || params->cq_off.user_addr != 0 ||
        (params->sq_off.array % _Alignof(uint32_t)) != 0 ||
        (params->cq_off.cqes % _Alignof(struct io_uring_cqe)) != 0)
        return 0;
    return 1;
}

static int setup_request_valid(const struct io_uring_params* params) {
    struct io_uring_params expected;
    memset(&expected, 0, sizeof(expected));
    expected.flags = IORING_SETUP_COOP_TASKRUN;
    return params != 0 && memcmp(params, &expected, sizeof(expected)) == 0;
}

static int range_valid(const void* base, size_t length, size_t offset, size_t field_length) {
    return base != 0 && offset <= length && field_length <= length - offset &&
           (uintptr_t)base <= UINTPTR_MAX - offset;
}

static int ranges_disjoint(const void* first,
                           size_t first_length,
                           const void* second,
                           size_t second_length) {
    const uintptr_t first_begin = (uintptr_t)first;
    const uintptr_t second_begin = (uintptr_t)second;
    if (first_begin > UINTPTR_MAX - first_length || second_begin > UINTPTR_MAX - second_length)
        return 0;
    return first_begin + first_length <= second_begin ||
           second_begin + second_length <= first_begin;
}

static int mapped_ring_identity_valid(void) {
    if (!ring_view.setup_valid || ring_view.sq_ring == 0 || ring_view.cq_ring == 0 ||
        ring_view.sqes == 0 || ring_view.sq_ring_length == 0 || ring_view.cq_ring_length == 0 ||
        ring_view.sqes_length == 0 ||
        ((uintptr_t)ring_view.sq_ring % (uintptr_t)getpagesize()) != 0 ||
        ((uintptr_t)ring_view.cq_ring % (uintptr_t)getpagesize()) != 0 ||
        ((uintptr_t)ring_view.sqes % (uintptr_t)getpagesize()) != 0 ||
        !ranges_disjoint(ring_view.sq_ring,
                         ring_view.sq_ring_length,
                         ring_view.cq_ring,
                         ring_view.cq_ring_length) ||
        !ranges_disjoint(
            ring_view.sq_ring, ring_view.sq_ring_length, ring_view.sqes, ring_view.sqes_length) ||
        !ranges_disjoint(
            ring_view.cq_ring, ring_view.cq_ring_length, ring_view.sqes, ring_view.sqes_length))
        return 0;
    const struct io_uring_params* params = &ring_view.params;
    if (!range_valid(ring_view.sq_ring, ring_view.sq_ring_length, params->sq_off.head, 4) ||
        !range_valid(ring_view.sq_ring, ring_view.sq_ring_length, params->sq_off.tail, 4) ||
        !range_valid(ring_view.sq_ring, ring_view.sq_ring_length, params->sq_off.ring_mask, 4) ||
        !range_valid(ring_view.sq_ring, ring_view.sq_ring_length, params->sq_off.ring_entries, 4) ||
        !range_valid(ring_view.sq_ring,
                     ring_view.sq_ring_length,
                     params->sq_off.array,
                     (size_t)params->sq_entries * sizeof(uint32_t)) ||
        !range_valid(ring_view.cq_ring, ring_view.cq_ring_length, params->cq_off.head, 4) ||
        !range_valid(ring_view.cq_ring, ring_view.cq_ring_length, params->cq_off.tail, 4) ||
        !range_valid(ring_view.cq_ring, ring_view.cq_ring_length, params->cq_off.ring_mask, 4) ||
        !range_valid(ring_view.cq_ring, ring_view.cq_ring_length, params->cq_off.ring_entries, 4) ||
        !range_valid(ring_view.cq_ring,
                     ring_view.cq_ring_length,
                     params->cq_off.cqes,
                     (size_t)params->cq_entries * sizeof(struct io_uring_cqe)) ||
        ring_view.sqes_length != (size_t)params->sq_entries * sizeof(struct io_uring_sqe))
        return 0;

    char* sq = (char*)ring_view.sq_ring;
    char* cq = (char*)ring_view.cq_ring;
    const uint32_t sq_entries =
        __atomic_load_n((uint32_t*)(sq + params->sq_off.ring_entries), __ATOMIC_ACQUIRE);
    const uint32_t sq_mask =
        __atomic_load_n((uint32_t*)(sq + params->sq_off.ring_mask), __ATOMIC_ACQUIRE);
    const uint32_t cq_entries =
        __atomic_load_n((uint32_t*)(cq + params->cq_off.ring_entries), __ATOMIC_ACQUIRE);
    const uint32_t cq_mask =
        __atomic_load_n((uint32_t*)(cq + params->cq_off.ring_mask), __ATOMIC_ACQUIRE);
    return sq_entries == params->sq_entries && cq_entries == params->cq_entries &&
           sq_entries != 0 && cq_entries != 0 && (sq_entries & (sq_entries - 1U)) == 0 &&
           (cq_entries & (cq_entries - 1U)) == 0 && sq_mask == sq_entries - 1U &&
           cq_mask == cq_entries - 1U;
}

static int ring_complete(void) {
    return ring_view.fd >= 0 && mapped_ring_identity_valid() && ring_view.pbuf_registered &&
           ring_view.buffer_data_mapping != 0 && ring_view.buffer_ring != 0 &&
           ring_view.buffer_entries == RUT_GATE_BUFFER_COUNT &&
           ring_view.buffer_group == RUT_GATE_BUFFER_GROUP;
}

static int runtime_ring_complete(void) {
    return rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_FAILED &&
           rut_downstream_gate_load(&gate->ring_ready) == 1 && ring_complete();
}

static int pbuf_registration_reserved_bytes_zero(const struct io_uring_buf_reg* registration) {
    if (registration == 0) return 0;
    const unsigned char* bytes = (const unsigned char*)registration;
    for (size_t i = RUT_GATE_PBUF_REG_RESERVED_OFFSET;
         i < RUT_GATE_PBUF_REG_RESERVED_OFFSET + RUT_GATE_PBUF_REG_RESERVED_SIZE;
         i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int pbuf_registration_valid(const struct io_uring_buf_reg* registration) {
    if (registration == 0 || ring_view.buffer_data_mapping == 0 ||
        ring_view.buffer_data_length != RUT_GATE_PBUF_DATA_SIZE ||
        ring_view.buffer_ring_mapping == 0 ||
        ring_view.buffer_ring_length != RUT_GATE_PBUF_RING_SIZE ||
        registration->ring_addr != (uint64_t)(uintptr_t)ring_view.buffer_ring_mapping ||
        registration->ring_entries != RUT_GATE_BUFFER_COUNT ||
        registration->bgid != RUT_GATE_BUFFER_GROUP || registration->flags != 0 ||
        !pbuf_registration_reserved_bytes_zero(registration) ||
        ((uintptr_t)ring_view.buffer_ring_mapping % (uintptr_t)getpagesize()) != 0 ||
        ((uintptr_t)ring_view.buffer_data_mapping % (uintptr_t)getpagesize()) != 0 ||
        !range_valid(ring_view.buffer_ring_mapping,
                     ring_view.buffer_ring_length,
                     0,
                     RUT_GATE_PBUF_RING_SIZE) ||
        !range_valid(ring_view.buffer_data_mapping,
                     ring_view.buffer_data_length,
                     0,
                     RUT_GATE_PBUF_DATA_SIZE) ||
        !ranges_disjoint(ring_view.buffer_ring_mapping,
                         ring_view.buffer_ring_length,
                         ring_view.buffer_data_mapping,
                         ring_view.buffer_data_length) ||
        !ranges_disjoint(ring_view.buffer_ring_mapping,
                         ring_view.buffer_ring_length,
                         ring_view.sq_ring,
                         ring_view.sq_ring_length) ||
        !ranges_disjoint(ring_view.buffer_ring_mapping,
                         ring_view.buffer_ring_length,
                         ring_view.cq_ring,
                         ring_view.cq_ring_length) ||
        !ranges_disjoint(ring_view.buffer_ring_mapping,
                         ring_view.buffer_ring_length,
                         ring_view.sqes,
                         ring_view.sqes_length) ||
        !ranges_disjoint(ring_view.buffer_data_mapping,
                         ring_view.buffer_data_length,
                         ring_view.sq_ring,
                         ring_view.sq_ring_length) ||
        !ranges_disjoint(ring_view.buffer_data_mapping,
                         ring_view.buffer_data_length,
                         ring_view.cq_ring,
                         ring_view.cq_ring_length) ||
        !ranges_disjoint(ring_view.buffer_data_mapping,
                         ring_view.buffer_data_length,
                         ring_view.sqes,
                         ring_view.sqes_length))
        return 0;
    return 1;
}

void* mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
    const long result = rut_gate_kernel_syscall(SYS_mmap,
                                                (unsigned long)address,
                                                length,
                                                (unsigned long)protection,
                                                (unsigned long)flags,
                                                (unsigned long)fd,
                                                (unsigned long)offset);
    if ((unsigned long)result >= (unsigned long)-4095) {
        errno = (int)-result;
        return MAP_FAILED;
    }
    void* mapped = (void*)result;
    int inject_duplicate = 0;
    int failed_now = 0;
    if (target_process) lock_identity();
    if (target_process && failed_locked()) {
        unlock_identity();
        return mapped;
    }
    if (target_process && ring_view.fd >= 0 && fd == ring_view.fd) {
        const char* owner_death = getenv("RUT_IOURING_GATE_INJECT_OWNER_DEATH");
        if ((uint64_t)offset == IORING_OFF_SQ_RING && owner_death != 0 &&
            strcmp(owner_death, "1") == 0)
            (void)rut_gate_kernel_syscall(SYS_exit_group, 86, 0, 0, 0, 0, 0);
        const size_t expected_sq_length = (size_t)ring_view.params.sq_off.array +
                                          (size_t)ring_view.params.sq_entries * sizeof(uint32_t);
        const size_t expected_cq_length =
            (size_t)ring_view.params.cq_off.cqes +
            (size_t)ring_view.params.cq_entries * sizeof(struct io_uring_cqe);
        const size_t expected_sqes_length =
            (size_t)ring_view.params.sq_entries * sizeof(struct io_uring_sqe);
        if (!ring_view.setup_valid || address != 0 || protection != (PROT_READ | PROT_WRITE) ||
            flags != (MAP_SHARED | MAP_POPULATE)) {
            fail_locked(RUT_IOURING_GATE_ERROR_RING);
            failed_now = 1;
        } else if ((uint64_t)offset == IORING_OFF_SQ_RING && length == expected_sq_length &&
                   ring_view.sq_ring == 0) {
            ring_view.sq_ring = mapped;
            ring_view.sq_ring_length = length;
            const char* inject = getenv("RUT_IOURING_GATE_INJECT_DUPLICATE_SQ");
            if (!duplicate_sq_mapping_injected && inject != 0 && strcmp(inject, "1") == 0) {
                duplicate_sq_mapping_injected = 1;
                inject_duplicate = 1;
            }
        } else if ((uint64_t)offset == IORING_OFF_CQ_RING && length == expected_cq_length &&
                   ring_view.cq_ring == 0) {
            ring_view.cq_ring = mapped;
            ring_view.cq_ring_length = length;
        } else if ((uint64_t)offset == IORING_OFF_SQES && length == expected_sqes_length &&
                   ring_view.sqes == 0) {
            ring_view.sqes = (struct io_uring_sqe*)mapped;
            ring_view.sqes_length = length;
        } else {
            fail_locked(RUT_IOURING_GATE_ERROR_RING);
            failed_now = 1;
        }
        if (!failed_now && ring_view.sq_ring != 0 && ring_view.cq_ring != 0 &&
            ring_view.sqes != 0 && !mapped_ring_identity_valid()) {
            fail_locked(RUT_IOURING_GATE_ERROR_RING);
            failed_now = 1;
        }
    } else if (target_process && fd == -1 && offset == 0 && address == 0 &&
               protection == (PROT_READ | PROT_WRITE) &&
               flags == (MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE) && ring_view.sq_ring != 0 &&
               ring_view.cq_ring != 0 && ring_view.sqes != 0) {
        if (length == RUT_GATE_PBUF_DATA_SIZE && ring_view.buffer_data_mapping == 0) {
            ring_view.buffer_data_mapping = mapped;
            ring_view.buffer_data_length = length;
        } else if (length == RUT_GATE_PBUF_RING_SIZE && ring_view.buffer_ring_mapping == 0) {
            ring_view.buffer_ring_mapping = mapped;
            ring_view.buffer_ring_length = length;
        } else if (length == RUT_GATE_PBUF_DATA_SIZE || length == RUT_GATE_PBUF_RING_SIZE) {
            fail_locked(RUT_IOURING_GATE_ERROR_BUFFER);
            failed_now = 1;
        }
    }
    if (target_process) unlock_identity();
    if (failed_now) rut_downstream_gate_wake(&gate->state);
    if (inject_duplicate) (void)mmap(address, length, protection, flags, fd, offset);
    return mapped;
}

static int inspect_submission(uint32_t to_submit) {
    lock_identity();
    const int complete = runtime_ring_complete();
    unlock_identity();
    if (!complete) {
        fail(RUT_IOURING_GATE_ERROR_RING);
        return 0;
    }
    const char expected[] = "HTTP/1.1 502 ";
    char* sq = (char*)ring_view.sq_ring;
    uint32_t* head = (uint32_t*)(sq + ring_view.params.sq_off.head);
    uint32_t* tail = (uint32_t*)(sq + ring_view.params.sq_off.tail);
    uint32_t* mask = (uint32_t*)(sq + ring_view.params.sq_off.ring_mask);
    uint32_t* array = (uint32_t*)(sq + ring_view.params.sq_off.array);
    const uint32_t first = __atomic_load_n(head, __ATOMIC_ACQUIRE);
    const uint32_t last = __atomic_load_n(tail, __ATOMIC_ACQUIRE);
    if (to_submit > last - first || last - first > ring_view.params.sq_entries) {
        fail(RUT_IOURING_GATE_ERROR_SQ);
        return 0;
    }
    for (uint32_t cursor = first; cursor != first + to_submit; cursor++) {
        const uint32_t index = array[cursor & *mask];
        if (index >= ring_view.params.sq_entries) {
            fail(RUT_IOURING_GATE_ERROR_SQ);
            return 0;
        }
        const struct io_uring_sqe* sqe = &ring_view.sqes[index];
        struct sockaddr_in upstream_address;
        const int target_connect =
            gate->target_upstream_ipv4_be != 0 && gate->target_upstream_port_be != 0
                ? target_upstream_connect(sqe, &upstream_address)
                : 0;
        if (target_connect < 0) return 0;
        if (target_connect > 0) {
            lock_identity();
            if (!failed_locked() && !append_connect_attempt_locked(sqe, &upstream_address)) {
                unlock_identity();
                rut_downstream_gate_wake(&gate->state);
                return 0;
            }
            const char* inject = getenv("RUT_IOURING_GATE_INJECT_DUPLICATE_CONNECT_JOURNAL");
            if (!failed_locked() && !duplicate_connect_journal_injected && inject != 0 &&
                strcmp(inject, "1") == 0) {
                duplicate_connect_journal_injected = 1;
                (void)append_connect_attempt_locked(sqe, &upstream_address);
                unlock_identity();
                rut_downstream_gate_wake(&gate->state);
                return 0;
            }
            unlock_identity();
        }
        if (sqe->opcode == IORING_OP_RECV && target_peer(sqe->fd)) {
            if (sqe->flags != IOSQE_BUFFER_SELECT || sqe->ioprio != IORING_RECV_MULTISHOT ||
                sqe->buf_group != RUT_GATE_BUFFER_GROUP || sqe->len != RUT_GATE_BUFFER_SIZE ||
                (sqe->user_data & 0xffU) != RUT_GATE_RECV_EVENT) {
                fail(RUT_IOURING_GATE_ERROR_RECV_OWNER);
                return 0;
            }
            if (ring_view.target_recv_user_data != 0 &&
                ring_view.target_recv_user_data != sqe->user_data) {
                fail(RUT_IOURING_GATE_ERROR_RECV_OWNER);
                return 0;
            }
            ring_view.target_recv_user_data = sqe->user_data;
        }
        if (sqe->opcode != IORING_OP_SEND || !target_peer(sqe->fd) ||
            sqe->len < sizeof(expected) - 1 || sqe->addr == 0 ||
            memcmp((const void*)(uintptr_t)sqe->addr, expected, sizeof(expected) - 1) != 0)
            continue;
        lock_identity();
        if (failed_locked() ||
            rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_ARMED) {
            unlock_identity();
            continue;
        }
        if (ring_view.target_recv_user_data == 0) {
            fail_locked(RUT_IOURING_GATE_ERROR_RECV_OWNER);
            unlock_identity();
            rut_downstream_gate_wake(&gate->state);
            return 0;
        }
        const uint32_t recv_conn_id =
            (uint32_t)((ring_view.target_recv_user_data >> 8) & 0xffffffU);
        const uint32_t send_conn_id = (uint32_t)((sqe->user_data >> 8) & 0xffffffU);
        if ((sqe->user_data & 0xffU) != RUT_GATE_SEND_EVENT || recv_conn_id != send_conn_id) {
            fail_locked(RUT_IOURING_GATE_ERROR_RECV_OWNER);
            unlock_identity();
            rut_downstream_gate_wake(&gate->state);
            return 0;
        }
        gate->ring_fd = ring_view.fd;
        gate->intercepted_fd = sqe->fd;
        gate->intercepted_opcode = sqe->opcode;
        gate->intercepted_length = sqe->len;
        gate->intercepted_user_data = sqe->user_data;
        gate->recv_user_data = ring_view.target_recv_user_data;
        gate->sq_head_at_hit = first;
        gate->sq_tail_at_hit = last;
        gate->intercepted_prefix_length = sizeof(expected) - 1;
        memcpy(gate->intercepted_prefix, expected, sizeof(expected) - 1);
        char* cq = (char*)ring_view.cq_ring;
        uint32_t* cq_head = (uint32_t*)(cq + ring_view.params.cq_off.head);
        gate->cq_head_at_hit = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
        uint32_t armed = RUT_DOWNSTREAM_GATE_ARMED;
        if (!__atomic_compare_exchange_n(&gate->state,
                                         &armed,
                                         RUT_DOWNSTREAM_GATE_HIT,
                                         0,
                                         __ATOMIC_RELEASE,
                                         __ATOMIC_ACQUIRE)) {
            fail_locked(RUT_IOURING_GATE_ERROR_TRANSITION);
            unlock_identity();
            rut_downstream_gate_wake(&gate->state);
            return 0;
        }
        unlock_identity();
        rut_downstream_gate_wake(&gate->state);
        return 2;
    }
    return 1;
}

static const unsigned char* buffer_bytes(uint16_t wanted) {
    uint64_t base = ring_view.buffer_ring->bufs[0].addr;
    if (base != (uint64_t)(uintptr_t)ring_view.buffer_data_mapping) return 0;
    for (uint32_t i = 0; i < ring_view.buffer_entries; i++) {
        const struct io_uring_buf* buffer = &ring_view.buffer_ring->bufs[i];
        if (buffer->bid != i || buffer->len != RUT_GATE_BUFFER_SIZE ||
            buffer->addr != base + (uint64_t)i * RUT_GATE_BUFFER_SIZE)
            return 0;
    }
    if (wanted >= ring_view.buffer_entries) return 0;
    return (const unsigned char*)(uintptr_t)(base + (uint64_t)wanted * RUT_GATE_BUFFER_SIZE);
}

static int witness_request_two(void) {
    if (gate->request_two_length == 0 ||
        gate->request_two_length > RUT_DOWNSTREAM_GATE_REQUEST_CAPACITY)
        return 0;
    char* cq = (char*)ring_view.cq_ring;
    uint32_t* head = (uint32_t*)(cq + ring_view.params.cq_off.head);
    uint32_t* tail = (uint32_t*)(cq + ring_view.params.cq_off.tail);
    uint32_t* mask = (uint32_t*)(cq + ring_view.params.cq_off.ring_mask);
    struct io_uring_cqe* cqes = (struct io_uring_cqe*)(cq + ring_view.params.cq_off.cqes);
    const uint32_t initial_head = gate->cq_head_at_hit;
    uint32_t cursor = initial_head;
    uint32_t copied = 0;
    uint32_t fragments = 0;
    int timer_seen = 0;
    const int64_t deadline = rut_downstream_gate_now_ms() + 5000;
    while (copied < gate->request_two_length && rut_downstream_gate_now_ms() < deadline) {
        if (__atomic_load_n(head, __ATOMIC_ACQUIRE) != initial_head) {
            fail(RUT_IOURING_GATE_ERROR_CQ);
            return 0;
        }
        const uint32_t current_tail = __atomic_load_n(tail, __ATOMIC_ACQUIRE);
        if (current_tail - initial_head > ring_view.params.cq_entries) {
            fail(RUT_IOURING_GATE_ERROR_CQ);
            return 0;
        }
        while (cursor != current_tail) {
            const struct io_uring_cqe* cqe = &cqes[cursor & *mask];
            if (cqe->user_data == ring_view.target_recv_user_data) {
                const uint32_t metadata_mask = (1U << IORING_CQE_BUFFER_SHIFT) - 1U;
                const uint32_t allowed = IORING_CQE_F_BUFFER | IORING_CQE_F_MORE | (1U << 2);
                const uint32_t metadata = cqe->flags & metadata_mask;
                if (cqe->res <= 0 || (metadata & IORING_CQE_F_BUFFER) == 0 ||
                    (metadata & IORING_CQE_F_MORE) == 0 || (metadata & ~allowed) != 0 ||
                    (uint32_t)cqe->res > RUT_GATE_BUFFER_SIZE ||
                    (uint32_t)cqe->res > gate->request_two_length - copied) {
                    fail(RUT_IOURING_GATE_ERROR_CQ);
                    return 0;
                }
                const uint16_t bid = (uint16_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
                const unsigned char* bytes = buffer_bytes(bid);
                if (bytes == 0) {
                    fail(RUT_IOURING_GATE_ERROR_BUFFER);
                    return 0;
                }
                if (memcmp(bytes, gate->request_two + copied, (size_t)cqe->res) != 0) {
                    fail(RUT_IOURING_GATE_ERROR_REQUEST_MISMATCH);
                    return 0;
                }
                copied += (uint32_t)cqe->res;
                fragments++;
                if (copied < gate->request_two_length && (cqe->flags & IORING_CQE_F_MORE) == 0) {
                    fail(RUT_IOURING_GATE_ERROR_CQ);
                    return 0;
                }
            } else {
                const uint64_t timer =
                    ((uint64_t)RUT_GATE_TIMER_CONN_ID << 8) | RUT_GATE_TIMEOUT_EVENT;
                if (timer_seen || cqe->user_data != timer || cqe->flags != 0 || cqe->res != 8) {
                    fail(RUT_IOURING_GATE_ERROR_CQ);
                    return 0;
                }
                timer_seen = 1;
            }
            cursor++;
        }
        if (copied < gate->request_two_length)
            (void)rut_gate_kernel_syscall(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    if (copied != gate->request_two_length) {
        fail(RUT_IOURING_GATE_ERROR_TIMEOUT);
        return 0;
    }
    if (__atomic_load_n(head, __ATOMIC_ACQUIRE) != initial_head) {
        fail(RUT_IOURING_GATE_ERROR_CQ);
        return 0;
    }
    lock_identity();
    if (failed_locked()) {
        unlock_identity();
        return 0;
    }
    gate->cq_tail_at_arrival = __atomic_load_n(tail, __ATOMIC_ACQUIRE);
    gate->witness_fragments = fragments;
    gate->witness_length = copied;
    unlock_identity();
    return 1;
}

static int hold_before_enter(void) {
    if (!rut_iouring_gate_wait_until(gate, RUT_DOWNSTREAM_GATE_R2_SENT, 5000)) {
        if (rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_FAILED)
            fail(RUT_IOURING_GATE_ERROR_TIMEOUT);
        return 0;
    }
    if (!witness_request_two()) return 0;
    lock_identity();
    if (failed_locked()) {
        unlock_identity();
        return 0;
    }
    if (!rut_downstream_gate_cas(
            &gate->state, RUT_DOWNSTREAM_GATE_R2_SENT, RUT_DOWNSTREAM_GATE_R2_ARRIVED)) {
        fail_locked(RUT_IOURING_GATE_ERROR_TRANSITION);
        unlock_identity();
        rut_downstream_gate_wake(&gate->state);
        return 0;
    }
    unlock_identity();
    rut_downstream_gate_wake(&gate->state);
    if (!rut_iouring_gate_wait_until(gate, RUT_DOWNSTREAM_GATE_RELEASED, 5000)) {
        if (rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_FAILED)
            fail(RUT_IOURING_GATE_ERROR_TIMEOUT);
        return 0;
    }
    return 1;
}

__attribute__((visibility("hidden"))) long rut_gate_io_uring_syscall(long number,
                                                                     unsigned long arg1,
                                                                     unsigned long arg2,
                                                                     unsigned long arg3,
                                                                     unsigned long arg4,
                                                                     unsigned long arg5,
                                                                     unsigned long arg6) {
    if (!target_process)
        return libc_result(rut_gate_kernel_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6));
    if (number == __NR_io_uring_setup) {
        const struct io_uring_params* parameters = (const struct io_uring_params*)arg2;
        const int production_entries = arg1 == RUT_GATE_RING_ENTRIES;
        const int production_request = production_entries && setup_request_valid(parameters);
        const long result = rut_gate_kernel_syscall(number, arg1, arg2, 0, 0, 0, 0);
        int failed_now = 0;
        lock_identity();
        if (!failed_locked()) {
            if (production_entries && !production_request) {
                fail_locked(RUT_IOURING_GATE_ERROR_RING);
                failed_now = 1;
            } else if (result >= 0 && production_request && ring_view.fd < 0 &&
                       setup_params_valid(parameters)) {
                ring_view.fd = (int)result;
                memcpy(&ring_view.params, (const void*)arg2, sizeof(ring_view.params));
                ring_view.setup_valid = 1;
                gate->ring_fd = ring_view.fd;
            } else if (result >= 0 && production_request) {
                fail_locked(RUT_IOURING_GATE_ERROR_RING);
                failed_now = 1;
            }
        }
        unlock_identity();
        if (failed_now) rut_downstream_gate_wake(&gate->state);
        return libc_result(result);
    }
    if (number == __NR_io_uring_register && (int)arg1 == ring_view.fd) {
        const struct io_uring_buf_reg* registration = (const struct io_uring_buf_reg*)arg3;
        struct io_uring_buf_reg registration_copy;
        memset(&registration_copy, 0, sizeof(registration_copy));
        lock_identity();
        const int already_failed = failed_locked();
        const int exact_request = !already_failed && arg2 == IORING_REGISTER_PBUF_RING &&
                                  arg4 == 1 && !ring_view.pbuf_registered &&
                                  pbuf_registration_valid(registration);
        if (exact_request) memcpy(&registration_copy, registration, sizeof(registration_copy));
        unlock_identity();
        const long result = rut_gate_kernel_syscall(number, arg1, arg2, arg3, arg4, 0, 0);
        int failed_now = 0;
        lock_identity();
        if (!failed_locked()) {
            if (!exact_request) {
                fail_locked(RUT_IOURING_GATE_ERROR_BUFFER);
                failed_now = 1;
            } else if (result >= 0) {
                ring_view.buffer_ring =
                    (struct io_uring_buf_ring*)(uintptr_t)registration_copy.ring_addr;
                ring_view.buffer_entries = registration_copy.ring_entries;
                ring_view.buffer_group = registration_copy.bgid;
                ring_view.pbuf_registered = 1;
                if (!ring_complete() ||
                    rut_downstream_gate_load(&gate->state) != RUT_DOWNSTREAM_GATE_DISARMED) {
                    fail_locked(RUT_IOURING_GATE_ERROR_BUFFER);
                    failed_now = 1;
                } else {
                    rut_downstream_gate_store(&gate->ring_ready, 1);
                }
            }
        }
        unlock_identity();
        if (failed_now) rut_downstream_gate_wake(&gate->state);
        return libc_result(result);
    }
    if (number == __NR_io_uring_enter && (int)arg1 == ring_view.fd) {
        const char* mutate = getenv("RUT_IOURING_GATE_INJECT_READY_MASK_MUTATION");
        if (!ready_mask_mutation_injected && mutate != 0 && strcmp(mutate, "1") == 0 &&
            rut_downstream_gate_load(&gate->ring_ready) == 1) {
            ready_mask_mutation_injected = 1;
            char* sq = (char*)ring_view.sq_ring;
            uint32_t* mask = (uint32_t*)(sq + ring_view.params.sq_off.ring_mask);
            const uint32_t original = __atomic_load_n(mask, __ATOMIC_ACQUIRE);
            __atomic_store_n(mask, original ^ 1U, __ATOMIC_RELEASE);
            if (!runtime_ring_complete()) fail(RUT_IOURING_GATE_ERROR_RING);
            __atomic_store_n(mask, original, __ATOMIC_RELEASE);
        }
        const int inspection = inspect_submission((uint32_t)arg2);
        if (inspection == 0) {
            errno = EPROTO;
            return -1;
        }
        if (inspection == 2 && !hold_before_enter()) {
            errno = EPROTO;
            return -1;
        }
    }
    return libc_result(rut_gate_kernel_syscall(number, arg1, arg2, arg3, arg4, arg5, arg6));
}
