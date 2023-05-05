#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>
#include <assert.h>

void simple_for_and_finished(mco_coro *co)
{
  int i = 0;
  int *args;
  mco_pop(co, &args, sizeof(args));
  for (i = 0; i < 10; ++i)
  {
    printf("Hello,  acrop_main %d\n", i);
    fflush(stdout);
    *args = i;
    mco_push(co, &args, sizeof(args));
    mco_yield(co);
  }
}

mco_coro *co_create(void (*func)(mco_coro *co), void *any)
{

  mco_coro *co;
  mco_desc desc = mco_desc_init(func, 0);
  desc.user_data = NULL;
  mco_create(&co, &desc);
  mco_push(co, &any, sizeof(any));
  mco_resume(co);
  return co;
}

int main()
{
  mco_coro *co;
  int val = 0;
  int k = 0;
  co = co_create(simple_for_and_finished, &val);
  for (;;) {
    mco_resume(co);
    mco_pop(co,(void)val, sizeof(val));
    fflush(stdout);
    if (k == 10){
      break;
    }
    printf("done with %d\n", k);
    assert(k == val);
    k += 1;
  }

  assert(9 == val);
  return 0;
}
