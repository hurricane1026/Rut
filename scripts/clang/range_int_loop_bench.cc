#include "rut/common/types.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace rut;

extern "C" u64 raw_loop(const u32*, u32);
extern "C" u64 wrapped_loop(const u32*, u32);

namespace {

constexpr u32 kSizes[] = {16, 4'096, 262'144, 4'194'304};
constexpr int kSamples = 41;
u32 data[kSizes[3]];

using Loop = u64 (*)(const u32*, u32);

u64 now_ns() {
    timespec time{};
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return u64{1'000'000'000} * static_cast<u64>(time.tv_sec) + static_cast<u64>(time.tv_nsec);
}

double sample(Loop loop, u32 size, u32 reps) {
    u64 sum = 0;
    const u64 start = now_ns();
    for (u32 i = 0; i < reps; ++i) sum += loop(data, size);
    const u64 elapsed = now_ns() - start;
    asm volatile("" : : "r"(sum) : "memory");
    return static_cast<double>(elapsed) / (static_cast<double>(size) * reps);
}

int compare_samples(const void* left, const void* right) {
    const double a = *static_cast<const double*>(left);
    const double b = *static_cast<const double*>(right);
    return (a > b) - (a < b);
}

int pin_to_one_core() {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return -1;
    int cpu = 0;
    for (; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) {
    }
    if (cpu == CPU_SETSIZE) return -1;
    cpu_set_t pinned;
    CPU_ZERO(&pinned);
    CPU_SET(cpu, &pinned);
    return sched_setaffinity(0, sizeof(pinned), &pinned) == 0 ? cpu : -1;
}

}  // namespace

int main() {
    const int cpu = pin_to_one_core();
    if (cpu < 0) {
        fprintf(stderr, "could not pin the benchmark to a single CPU\n");
        return 1;
    }
    printf("Pinned CPU %d\n", cpu);

    u32 seed = 0x243f6a88;
    for (auto& value : data) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        value = seed;
    }

    for (u32 size : kSizes) {
        if (raw_loop(data, size) != wrapped_loop(data, size)) {
            fprintf(stderr, "loop results differ at size %u\n", size);
            return 1;
        }
        const u32 repeats = 8'388'608 / size;
        const u32 reps = repeats < 150'000 ? repeats : 150'000;
        for (int i = 0; i < 3; ++i) {
            sample(raw_loop, size, reps);
            sample(wrapped_loop, size, reps);
        }

        double raw[kSamples], wrapped[kSamples], ratio[kSamples];
        for (int i = 0; i < kSamples; ++i) {
            if (i % 2 == 0) {
                raw[i] = sample(raw_loop, size, reps);
                wrapped[i] = sample(wrapped_loop, size, reps);
            } else {
                wrapped[i] = sample(wrapped_loop, size, reps);
                raw[i] = sample(raw_loop, size, reps);
            }
            ratio[i] = wrapped[i] / raw[i] * 100.0;
        }
        qsort(raw, kSamples, sizeof(double), compare_samples);
        qsort(wrapped, kSamples, sizeof(double), compare_samples);
        qsort(ratio, kSamples, sizeof(double), compare_samples);
        printf(
            "%8u  raw %.4f ns/elem  wrapped %.4f ns/elem  ratio %.2f%% [p10 %.2f%%, p90 %.2f%%]\n",
            size,
            raw[kSamples / 2],
            wrapped[kSamples / 2],
            ratio[kSamples / 2],
            ratio[kSamples / 10],
            ratio[kSamples * 9 / 10]);
    }
}
