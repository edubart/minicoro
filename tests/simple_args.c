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

int main()
{
  mco_coro *co;
  int val = 0;
  int k = 0;
  co = mco_start(simple_for_and_finished, NULL, &val);
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

  return 0;
}
