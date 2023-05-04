/*****
 * cothread parameterized function example
 *****
 * entry point to cothreads cannot take arguments.
 * this is due to portability issues: each processor,
 * operating system, programming language and compiler
 * can use different parameter passing methods, so
 * arguments to the cothread entry points were omitted.
 *
 * however, the behavior can easily be simulated by use
 * of a specialized co_switch to set global parameters to
 * be used as function arguments.
 *
 * in this way, with a bit of extra red tape, one gains
 * even more flexibility than would be possible with a
 * fixed argument list entry point, such as void (*)(void*),
 * as any number of arguments can be used.
 *
 * this also eliminates race conditions where a pointer
 * passed to co_create may have changed or become invalidated
 * before call to co_switch, as said pointer would now be set
 * when calling co_switch, instead.
 *****/

#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// one could also call this co_init or somesuch if they preferred ...
mco_result co_switch(mco_coro *co, int param_y){

    mco_push(co, &param_y, sizeof(param_y));
    return mco_yield(co);
}

mco_result co_create(mco_coro *co, void (*func)(mco_coro *co), void *any)
{
    mco_desc desc = mco_desc_init(func, 0);
    desc.user_data = NULL;
    mco_create(&co, &desc);
    mco_push(co, &any, sizeof(any));
    return mco_resume(co);
}

void co_entrypoint(mco_coro *co)
{
    int param_x, param_y;
    mco_pop(co, &param_y, sizeof(param_y));
    printf("co_entrypoint(%d)\n", (int)param_y);
    co_switch(co, param_y);
    // co_switch(co, param_y);

    // co_arg::param_x will change here (due to co_switch(cothread_t, int, int) call changing values),
    // however, param_x and param_y will persist as they are thread local

    printf("co_entrypoint(%d)\n", (int)param_y);
    co_switch(co, param_y);
}

int main() {
  printf("cothread parameterized function example\n\n");

  mco_coro *co[3];
  int ret = 0;

  /* Create coroutine */
  co_create(co[0], co_entrypoint, (void *)sizeof(ret));

  co_create(co[1], co_entrypoint, (void*)1);

  co_create(co[2], co_entrypoint, (void *)4);

  // use specialized co_switch(cothread_t, int, int) for initial co_switch call

  // after first call, entry point arguments have been initialized, standard
  // co_switch(cothread_t) can be used from now on
  mco_resume(co[2]);
  mco_resume(co[1]);

  printf("\ndone\n");
  return 0;
}
