#define MINICORO_IMPL
#define MCO_NO_DEBUG 1
#include "minicoro.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum
{
    Iterations = 500000000
};

static int counter;

void co_timingtest(mco_coro *co)
{
    for (;;)
    {
        counter++;
        mco_yield(co);
    }
}

void sub_timingtest()
{
    counter++;
}

int main()
{
    printf("context-switching timing test\n\n");
    time_t start, end;
    mco_coro *thread_y;
    int i, t1, t2;

    start = clock();
    for (counter = 0, i = 0; i < Iterations; i++)
    {
        sub_timingtest();
    }
    end = clock();

    t1 = (int)difftime(end, start);
    printf("%2.3f seconds per  50 million subroutine calls (%d iterations)\n", (float)t1 / CLOCKS_PER_SEC, counter);

    thread_y = mco_start(co_timingtest, NULL, NULL);
    start = clock();
    for (counter = 0, i = 0; i < Iterations; i++)
    {
        mco_resume(thread_y);
    }
    end = clock();

    mco_destroy(thread_y);

    t2 = (int)difftime(end, start);
    printf("%2.3f seconds per 100 million mco_resume calls (%d iterations)\n", (float)t2 / CLOCKS_PER_SEC, counter);

    printf("mco_resume skew = %fx\n\n", (double)t2 / (double)t1);
    return 0;
}
