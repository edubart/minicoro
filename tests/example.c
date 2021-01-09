#define MINICORO_IMPL

#include "minicoro.h"
#include <stdio.h>

static void fail(const char* message) {
  puts(message);
  exit(-1);
}

static void fibonnaci_coro(mco_coro* co) {
  uint64_t m = 1;
  uint64_t n = 1;
  while(1) {
    mco_set_user_data(co, &m, sizeof(m));
    if(mco_yield(co) != MCO_SUCCESS)
      fail("Failed to yield coroutine");
    uint64_t tmp = m + n;
    m = n;
    n = tmp;
    if(m > 0xffffffff)
      break;
  }
}

int main() {
  mco_coro* co;
  mco_error err;

  /* Create the coroutine. */
  err = mco_create(&co, (mco_desc){.func=fibonnaci_coro});
  if(err != MCO_SUCCESS)
    fail("Failed to created coroutine");

  int counter = 1;
  while(mco_status(co) == MCO_SUSPENDED) {
    /* Resume the coroutine. */
    err = mco_resume(co);
    if(err != MCO_SUCCESS)
      fail("Failed to resume coroutine");

    /* Retrieve user data set in last coroutine yield. */
    uint64_t res;
    if(mco_get_user_data(co, &res, sizeof(res)) != MCO_SUCCESS)
      fail("Failed to retrieve coroutine user data");
    printf("fib %d = %lu\n", counter, res);
    counter = counter + 1;
  }

  /* Destroy the coroutine. */
  err = mco_destroy(co);
  return 0;
}
