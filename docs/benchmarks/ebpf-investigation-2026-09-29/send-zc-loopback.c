#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed line %d: %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
int main(void) {
    alarm(10);
    const unsigned length = 512 * 1024;
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t size = sizeof(addr);
    CHECK(getsockname(listener, (struct sockaddr *)&addr, &size) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        alarm(10);
        int input = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (input < 0) _exit(2);
        close(listener);
        unsigned total = 0;
        unsigned char buffer[16384];
        while (total < length) {
            ssize_t n = read(input, buffer, sizeof(buffer));
            if (n <= 0) _exit(3);
            for (ssize_t i = 0; i < n; ++i) if (buffer[i] != 0x5a) _exit(4);
            total += (unsigned)n;
        }
        close(input);
        _exit(total == length ? 0 : 5);
    }
    close(listener);
    int output = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(output >= 0);
    CHECK(connect(output, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    unsigned char *data = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(data != MAP_FAILED);
    memset(data, 0x5a, length);
    struct io_uring_params p = {0};
    int ring = syscall(__NR_io_uring_setup, 8, &p);
    CHECK(ring >= 0);
    size_t sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    char *sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
    char *cq = mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries * sizeof(*sqes), PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
    CHECK(sq != MAP_FAILED && cq != MAP_FAILED && sqes != MAP_FAILED);
    unsigned *sq_tail = (void *)(sq + p.sq_off.tail);
    unsigned *sq_array = (void *)(sq + p.sq_off.array);
    unsigned *cq_head = (void *)(cq + p.cq_off.head);
    unsigned *cq_tail = (void *)(cq + p.cq_off.tail);
    unsigned cq_mask = *(unsigned *)(cq + p.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (void *)(cq + p.cq_off.cqes);
    struct io_uring_sqe *entry = &sqes[0];
    memset(entry, 0, sizeof(*entry));
    entry->opcode = IORING_OP_SEND_ZC;
    entry->fd = output;
    entry->addr = (uintptr_t)data;
    entry->len = length;
    entry->msg_flags = MSG_NOSIGNAL;
    entry->ioprio = IORING_SEND_ZC_REPORT_USAGE;
    entry->user_data = 1;
    sq_array[0] = 0;
    __atomic_store_n(sq_tail, 1, __ATOMIC_RELEASE);
    CHECK(syscall(__NR_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1);
    int got_send = 0, got_notif = 0, expects_notif = 0;
    int32_t send_result = 0, notif_result = 0;
    unsigned send_flags = 0, notif_flags = 0;
    while (!got_send || (expects_notif && !got_notif)) {
        unsigned head = __atomic_load_n(cq_head, __ATOMIC_RELAXED);
        unsigned tail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
        if (head == tail) {
            CHECK(syscall(__NR_io_uring_enter, ring, 0, 1, IORING_ENTER_GETEVENTS, NULL, 0) >= 0);
            continue;
        }
        struct io_uring_cqe event = cqes[head & cq_mask];
        CHECK(event.user_data == 1);
        __atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
        if (event.flags & IORING_CQE_F_NOTIF) {
            CHECK(!got_notif);
            got_notif = 1; notif_result = event.res; notif_flags = event.flags;
        } else {
            CHECK(!got_send);
            got_send = 1; send_result = event.res; send_flags = event.flags;
            expects_notif = !!(event.flags & IORING_CQE_F_MORE);
            CHECK(event.res == (int32_t)length);
        }
    }
    CHECK(got_notif);
    close(output);
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("{\"length\":%u,\"send_result\":%d,\"send_flags\":%u,\"notification_result\":%u,\"notification_flags\":%u,\"copied\":%s,\"body_verified\":true}\n", length, send_result, send_flags, (uint32_t)notif_result, notif_flags, ((uint32_t)notif_result & IORING_NOTIF_USAGE_ZC_COPIED) ? "true" : "false");
    munmap(data, length);
    munmap(sqes, p.sq_entries * sizeof(*sqes));
    munmap(sq, sq_size); munmap(cq, cq_size); close(ring);
    return 0;
}
