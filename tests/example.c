#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>

static void fail(const char* message, mco_result res) {
  printf("%s: %s", message, mco_result_description(res));
  exit(-1);
}

static void fibonacci_coro(mco_coro* co) {
  unsigned long m = 1;
  unsigned long n = 1;

  /* Retrieve max value. */
  unsigned long max;
  if(mco_get_storage(co, &max, sizeof(max)) != sizeof(max))
    fail("Failed to retrieve coroutine io data", MCO_GENERIC_ERROR);

  while(1) {
    /* Yield the next Fibonacci number. */
    mco_set_storage(co, &m, sizeof(m));
    mco_result res = mco_yield(co);
    if(res != MCO_SUCCESS)
      fail("Failed to yield coroutine", res);

    unsigned long tmp = m + n;
    m = n;
    n = tmp;
    if(m >= max)
      break;
  }
}

int main() {
  /* Create the coroutine. */
  mco_coro* co;
  mco_desc desc = mco_desc_init(fibonacci_coro, 0);
  mco_result res = mco_create(&co, &desc);
  if(res != MCO_SUCCESS)
    fail("Failed to create coroutine", res);

  /* Set io data. */
  unsigned long max = 1000000000;
  mco_set_storage(co, &max, sizeof(max));

  int counter = 1;
  while(mco_status(co) == MCO_SUSPENDED) {
    /* Resume the coroutine. */
    res = mco_resume(co);
    if(res != MCO_SUCCESS)
      fail("Failed to resume coroutine", res);

    /* Retrieve io data set in last coroutine yield. */
    unsigned long ret = 0;
    if(mco_get_storage(co, &ret, sizeof(ret)) != sizeof(ret))
      fail("Failed to retrieve coroutine io data", MCO_GENERIC_ERROR);
    printf("fib %d = %lu\n", counter, ret);
    counter = counter + 1;
  }

  /* Destroy the coroutine. */
  res = mco_destroy(co);
  if(res != MCO_SUCCESS)
    fail("Failed to destroy coroutine", res);
  return 0;
}
