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

void co_entrypoint(void *args, ...)
{
    int param_y = mco_value(args).integer;

    printf("co_entrypoint(%d)\n", param_y);
    mco_push(mco_active(), &param_y, sizeof(param_y));
    mco_suspend();

    mco_pop(mco_running(), &param_y, sizeof(param_y));
    printf("co_entrypoint 2(%d)\n", param_y);
    mco_push(mco_running(), &param_y, sizeof(param_y));
    mco_suspend();
}

int main()
{
    printf("cothread parameterized function example\n\n");

    mco_coro *co[3];
    int ret = 0;

    /* Create coroutine */
    co[0] = mco_await(co_entrypoint, (void *)sizeof(ret));

    co[1] = mco_await(co_entrypoint, (void *)1);

    co[2] = mco_await(co_entrypoint, (void *)10);

    mco_resume(co[2]);
    mco_resume(co[1]);
    mco_resume(co[0]);

    printf("\ndone\n");

    mco_destroy(co[0]);
    mco_destroy(co[1]);
    mco_destroy(co[2]);
    return 0;
}
