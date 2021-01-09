#define MCO_ZERO_MEMORY
#define MINICORO_IMPL

#include "minicoro.h"
#include <assert.h>
#include <stdio.h>

void coro_entry2(mco_coro* co2) {
  mco_coro* co;

  assert(mco_running() == co2);
  assert(mco_status(co2) == MCO_RUNNING);
  assert(mco_get_and_reset_user_data(co2, &co, sizeof(co)) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_NORMAL);
  assert(mco_get_user_data(co2, &co, sizeof(co)) == MCO_NO_USER_DATA);
  printf("hello 2\n");
  assert(mco_yield(co2) == MCO_SUCCESS);
  printf("world! 2\n");
}

void coro_entry(mco_coro* co) {
  char buffer[128];
  int ret;
  mco_coro* co2;

  /* Startup checks */
  assert(mco_running() == co);
  assert(mco_status(co) == MCO_RUNNING);

  /* Get user data 1 */
  assert(mco_get_user_data(co, buffer, 128) == MCO_SUCCESS);
  assert(mco_get_user_data_size(co) == 6);
  assert(strcmp(buffer, "hello") == 0);
  puts(buffer);

  /* Set user data 1 */
  ret = 1;
  assert(mco_set_user_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);

  /* Yield 1 */
  assert(mco_yield(co) == MCO_SUCCESS);

  /* Get user data 2 */
  assert(mco_get_user_data(co, buffer, 128) == MCO_SUCCESS);
  assert(mco_get_user_data_size(co) == 7);
  assert(strcmp(buffer, "world!") == 0);
  puts(buffer);

  /* Set user data 2 */
  ret = 2;
  assert(mco_set_user_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);

  /* Nested coroutine test */
  assert(mco_create(&co2, (mco_desc){.func=coro_entry2}) == MCO_SUCCESS);
  assert(mco_set_user_data(co2, &co, sizeof(co)) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_get_user_data(co2, &co, sizeof(co)) == MCO_NO_USER_DATA);
  assert(mco_status(co2) == MCO_DEAD);
  assert(mco_status(co) == MCO_RUNNING);
  assert(mco_running() == co);
}

int main() {
  mco_coro* co;
  int ret;

  /* Create coroutine */
  assert(mco_create(&co, (mco_desc){.func=coro_entry}) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* Set user data 1 */
  const char first_word[] = "hello";
  assert(mco_set_user_data(co, first_word, sizeof(first_word)) == MCO_SUCCESS);

  /* Resume 1 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* Get user data 1 */
  assert(mco_get_user_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);
  assert(ret == 1);

  /* Set user data 2 */
  const char second_word[] = "world!";
  assert(mco_set_user_data(co, second_word, sizeof(second_word)) == MCO_SUCCESS);

  /* Resume 2 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_DEAD);

  /* Get user data 2 */
  assert(mco_get_user_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);
  assert(ret == 2);

  /* Destroy */
  assert(mco_destroy(co) == MCO_SUCCESS);
  return 0;
}
