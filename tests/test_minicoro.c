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
  assert(mco_get_user_data(co2, &co, sizeof(co)) == MCO_NO_DATA);
  printf("hello 2\n");
  assert(mco_yield(co2) == MCO_SUCCESS);
  printf("world! 2\n");
}

void coro_entry(mco_coro* co) {
  char buffer[128];
  int res;
  mco_coro* co2;

  assert(mco_running() == co);
  assert(mco_status(co) == MCO_RUNNING);

  /* get user data 1 */
  assert(mco_get_user_data(co, buffer, 128) == MCO_SUCCESS);
  assert(mco_get_user_data_size(co) == 6);
  assert(strcmp(buffer, "hello") == 0);
  puts(buffer);

  /* set user data 1 */
  res = 1;
  assert(mco_set_user_data(co, &res, sizeof(res)) == MCO_SUCCESS);

  /* yield 1 */
  assert(mco_yield(co) == MCO_SUCCESS);

  /* get user data 2 */
  assert(mco_get_user_data(co, buffer, 128) == MCO_SUCCESS);
  assert(mco_get_user_data_size(co) == 7);
  assert(strcmp(buffer, "world!") == 0);
  puts(buffer);

  /* set user data 2 */
  res = 2;
  assert(mco_set_user_data(co, &res, sizeof(res)) == MCO_SUCCESS);

  /* inner coroutine test */
  assert(mco_create(&co2, (mco_desc){.func=coro_entry2}) == MCO_SUCCESS);
  assert(mco_set_user_data(co2, &co, sizeof(co)) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_get_user_data(co2, &co, sizeof(co)) == MCO_NO_DATA);
  assert(mco_status(co2) == MCO_DEAD);
  assert(mco_status(co) == MCO_RUNNING);
  assert(mco_running() == co);
}

int main() {
  mco_coro* co;
  int res;

  /* create coroutine */
  assert(mco_create(&co, (mco_desc){.func=coro_entry}) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* set user data 1 */
  const char first_word[] = "hello";
  assert(mco_set_user_data(co, first_word, sizeof(first_word)) == MCO_SUCCESS);

  /* resume 1 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* get user data 1 */
  assert(mco_get_user_data(co, &res, sizeof(res)) == MCO_SUCCESS);
  assert(res == 1);

  /* set user data 2 */
  const char second_word[] = "world!";
  assert(mco_set_user_data(co, second_word, sizeof(second_word)) == MCO_SUCCESS);

  /* resume 2 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_DEAD);

  /* get user data 2 */
  assert(mco_get_user_data(co, &res, sizeof(res)) == MCO_SUCCESS);
  assert(res == 2);

  /* destroy */
  assert(mco_destroy(co) == MCO_SUCCESS);
  return 0;
}
