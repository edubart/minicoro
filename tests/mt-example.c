#define MINICORO_IMPL
#include "minicoro.h"
#define C89THREAD_IMPLEMENTATION
#include "thirdparty/c89thread.h"
#include <stdio.h>

#define NUM_THREADS 4
#define NUM_TASKS 100
#define NUM_ITERATIONS 500
#define EXPECTED_RESULT 2396583362

static c89mtx_t mutex;
static c89thrd_t threads[NUM_THREADS];
static mco_coro* tasks[NUM_TASKS];

static void fail_mco(const char* message, mco_result res) {
  printf("%s: %s\n", message, mco_result_description(res));
  exit(-1);
}

static void fail(const char* message) {
  printf("%s\n", message);
  exit(-1);
}

static void fibonacci_task(mco_coro* co) {
  unsigned int m = 1;
  unsigned int n = 1;

  for(unsigned int i=0;i<NUM_ITERATIONS;++i) {
    /* Yield the next Fibonacci number. */
    mco_result res = mco_yield(co);
    if(res != MCO_SUCCESS)
      fail_mco("Failed to yield coroutine", res);

    unsigned int tmp = m + n;
    m = n;
    n = tmp;
  }

  /* Yield the last Fibonacci number. */
  mco_push(co, &m, sizeof(m));
}

static mco_coro* create_fibonacci_task() {
  /* Create the coroutine. */
  mco_coro* co;
  mco_desc desc = mco_desc_init(fibonacci_task, 0);
  mco_result res = mco_create(&co, &desc);
  if(res != MCO_SUCCESS)
    fail_mco("Failed to create coroutine", res);

  /* Return the task as a coroutine. */
  return co;
}

int thread_worker(void* data) {
  (void)data;

  while(1) {
    mco_coro* task = NULL;
    int task_id = 0;

    if(c89mtx_lock(&mutex) != c89thrd_success)
      fail("Unable to lock mutex");
    for(int i=0;i<NUM_TASKS;++i) {
      if(tasks[i] != NULL) {
        task = tasks[i];
        tasks[i] = NULL;
        task_id = i;
        break;
      }
    }
    if(c89mtx_unlock(&mutex) != c89thrd_success)
      fail("Unable to unlock mutex");

    if(!task) {
      /* All tasks finished. */
      return 0;
    }

    mco_result res = mco_resume(task);
    if(res != MCO_SUCCESS)
      fail_mco("Failed to yield coroutine", res);

    switch(mco_status(task)) {
      case MCO_SUSPENDED: { /* Task is not finished yet. */
        /* Add it back to task list. */
        if(c89mtx_lock(&mutex) != c89thrd_success)
          fail("Unable to lock mutex");
        tasks[task_id] = task;
        if(c89mtx_unlock(&mutex) != c89thrd_success)
          fail("Unable to unlock mutex");
        break;
      }
      case MCO_DEAD: { /* Task finished. */
        /* Retrieve storage set in last coroutine yield. */
        unsigned int ret = 0;
        res = mco_pop(task, &ret, sizeof(ret));
        if(res != MCO_SUCCESS)
          fail_mco("Failed to retrieve coroutine storage", res);
        /* Check task result. */
        if(ret != EXPECTED_RESULT) {
          printf("Unexpected result %u\n", ret);
          exit(-1);
        }
        /* Destroy the task. */
        mco_result res = mco_destroy(task);
        if(res != MCO_SUCCESS)
          fail_mco("Failed to destroy coroutine", res);
        break;
      }
      default: {
        fail("Unexpected task state");
        break;
      }
    }
  }
  return 0;
}

int main() {
  /* Initialize mutex. */
  if(c89mtx_init(&mutex, c89mtx_plain) != c89thrd_success)
    fail("Failed to create mutex");

  /* Create coroutine tasks. */
  for(int i=0;i<NUM_TASKS;++i) {
    tasks[i] = create_fibonacci_task();
  }

  /* Create thread workers. */
  for(size_t i=0;i<NUM_THREADS;++i) {
    if(c89thrd_create(&threads[i], thread_worker, NULL) != c89thrd_success)
      fail("Failed to create a thread");
  }

  /* Wait all threads to finish. */
  for(size_t i=0;i<NUM_THREADS;++i) {
    if(c89thrd_join(threads[i], NULL) != c89thrd_success)
      fail("Failed to join a thread!");
  }

  for(int i=0;i<NUM_TASKS;++i) {
    if(tasks[i] != NULL)
      fail("A task is unfinished");
  }

  /* Destroy mutex. */
  c89mtx_destroy(&mutex);

  printf("Multithread test succeeded!\n");
  return 0;
}
