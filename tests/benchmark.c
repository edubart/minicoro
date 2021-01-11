#define MINICORO_IMPL
#include "minicoro.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__i386__)
static inline uint64_t rdtsc() {
  uint64_t x;
  __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
  return x;
}
#elif defined(__x86_64__)
static inline uint64_t rdtsc() {
  uint32_t hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (uint64_t)lo)|( ((uint64_t)hi)<<32 );
}
#endif

#define SWITCH_ITERATIONS 10000000
#define INIT_ITERATIONS   100000

void coro_entry(mco_coro* co) {
  for(int i=0;i<SWITCH_ITERATIONS;++i) {
    mco_yield(co);
  }
}

void bench_switch() {
  mco_desc desc = mco_desc_init(coro_entry, 0);
  mco_coro* co;
  mco_create(&co, &desc);
  uint64_t start = rdtsc();
  for(int i=0;i<SWITCH_ITERATIONS;++i) {
    mco_resume(co);
  }
  uint64_t elapsed = rdtsc() - start;
  mco_destroy(co);
  printf("switch cycles %.1f\n", elapsed / (double)(SWITCH_ITERATIONS*2));
}

void bench_init() {
  mco_desc desc = mco_desc_init(coro_entry, 0);
  mco_coro* co = (mco_coro*)malloc(desc.coro_size);
  uint64_t init_cycles = 0;
  uint64_t uninit_cycles = 0;
  uint64_t start;
  for(int i=0;i<INIT_ITERATIONS;++i) {
    start = rdtsc();
    mco_init(co, &desc);
    init_cycles += rdtsc() - start;

    start = rdtsc();
    mco_uninit(co);
    uninit_cycles += rdtsc() - start;
  }
  free(co);
  printf("init cycles %.1f\n", init_cycles / (double)(INIT_ITERATIONS));
  printf("uninit cycles %.1f\n", uninit_cycles / (double)(INIT_ITERATIONS));
}

int main() {
  bench_switch();
  bench_init();
  return 0;
}
