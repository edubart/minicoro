#define MINICORO_IMPL
#define MCO_USE_VMEM_ALLOCATOR
#include "minicoro.h"
#include <stdio.h>
#include <assert.h>

#define NUM_COROS 100*1000
mco_coro* coros[NUM_COROS];

// Coroutine entry function.
void coro_entry(mco_coro* co) {
  mco_yield(co);
}

int main() {
  // First initialize a `desc` object through `mco_desc_init`.
  mco_desc desc = mco_desc_init(coro_entry, 0);

  for (int i=0; i < NUM_COROS; ++i) {
    mco_coro* co = NULL;
    mco_result res = mco_create(&co, &desc);
    assert(res == MCO_SUCCESS);
    assert(mco_status(co) == MCO_SUSPENDED);
    res = mco_resume(co);
    coros[i] = co;
  }

  printf("Created %d coroutines, press enter to quit...\n", NUM_COROS);
  getchar();

  for (int i=0; i < NUM_COROS; ++i) {
    mco_coro* co = coros[i];
    mco_result res = mco_resume(co);
    assert(res == MCO_SUCCESS);
    assert(mco_status(co) == MCO_DEAD);
    res = mco_destroy(co);
    assert(res == MCO_SUCCESS);
  }

  return 0;
}
