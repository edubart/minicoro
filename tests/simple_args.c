#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>
#include <assert.h>

void simple_for_and_finished(mco_coro *co)
{
  int i = 0;
  int args;
  mco_pop(co, &args, sizeof(args));
  for (i = 0; i < 10; ++i)
  {
    printf("Hello, main %d\n", i);
    fflush(stdout);
    args = i;
    mco_push(co, &args, sizeof(args));
    mco_suspend();
  }

  mco_push(co, &args, sizeof(args));
}

void simple_print(void *args, ...)
{
  mco_suspend();
  assert(mco_get_bytes_stored(mco_running()) == 0);
  printf("Hello, await with args: %s\n", mco_value(args).chars);
}

int main()
{
  mco_coro *co, *co1, *co2;
  int val = 0;
  int k = 0;
  char *test = (char *)"world\0";
  char *test2 = (char *)"ok\0";
  co = mco_start(simple_for_and_finished, NULL, &val);
  co1 = mco_await(simple_print, (void *)test);
  mco_resume(co1);
  for (;;) {
    if (k == 10)
    {
      break;
    }
    assert(k == val);
    mco_wait();
    mco_pop(co, &val, sizeof(val));
    k += 1;
  }

  assert(9 == val);
  mco_destroy(co);
  mco_destroy(co1);

  co2 = mco_await(simple_print, (void *)test2);
  mco_resume(co2);
  mco_destroy(co2);

  return 0;
}
