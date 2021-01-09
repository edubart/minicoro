#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>

static void fail(const char* message, mco_result res) {
  printf("%s: %s", message, mco_result_description(res));
  exit(-1);
}

static void fibonnaci_coro(mco_coro* co) {
  uint64_t m = 1;
  uint64_t n = 1;
  while(1) {
    mco_set_user_data(co, &m, sizeof(m));
    mco_result res = mco_yield(co);
    if(res != MCO_SUCCESS)
      fail("Failed to yield coroutine", res);
    uint64_t tmp = m + n;
    m = n;
    n = tmp;
    if(m > 0xffffffff)
      break;
  }
}

int main() {
  /* Create the coroutine. */
  mco_coro* co;
  mco_result res = mco_create(&co, (mco_desc){.func=fibonnaci_coro});
  if(res != MCO_SUCCESS)
    fail("Failed to created coroutine", res);

  int counter = 1;
  while(mco_status(co) == MCO_SUSPENDED) {
    /* Resume the coroutine. */
    res = mco_resume(co);
    if(res != MCO_SUCCESS)
      fail("Failed to resume coroutine", res);

    /* Retrieve user data set in last coroutine yield. */
    uint64_t ret;
    if(mco_get_user_data(co, &ret, sizeof(ret)) != MCO_SUCCESS)
      fail("Failed to retrieve coroutine user data", res);
    printf("fib %d = %lu\n", counter, ret);
    counter = counter + 1;
  }

  /* Destroy the coroutine. */
  res = mco_destroy(co);
  return 0;
}
