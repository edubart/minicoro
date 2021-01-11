#define MCO_ZERO_MEMORY
#define MINICORO_IMPL

#include "minicoro.h"
#include <assert.h>
#include <stdio.h>

void coro_entry2(mco_coro* co2) {
  mco_coro* co = NULL;

  assert(mco_running() == co2);
  assert(mco_status(co2) == MCO_RUNNING);
  assert(mco_get_io_data(co2, &co, sizeof(co)) == sizeof(co));
  assert(mco_reset_io_data(co2) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_NORMAL);
  assert(mco_get_io_data(co2, &co, sizeof(co)) == 0);
  printf("hello 2\n");
  assert(mco_yield(mco_running()) == MCO_SUCCESS);
  printf("world! 2\n");
}

int dummy_user_data = 0;

void coro_entry(mco_coro* co) {
  char buffer[128] = {0};
  int ret;
  mco_coro* co2;

  /* Startup checks */
  assert(mco_get_user_data(co) == &dummy_user_data);
  assert(mco_running() == co);
  assert(mco_status(co) == MCO_RUNNING);

  /* Get io data 1 */
  assert(mco_get_io_data(co, buffer, 128) == 6);
  assert(mco_get_io_data_size(co) == 6);
  assert(strcmp(buffer, "hello") == 0);
  puts(buffer);

  /* Set io data 1 */
  ret = 1;
  assert(mco_set_io_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);

  /* Yield 1 */
  assert(mco_yield(co) == MCO_SUCCESS);

  /* Get io data 2 */
  assert(mco_get_io_data(co, buffer, 128) == 7);
  assert(mco_get_io_data_size(co) == 7);
  assert(strcmp(buffer, "world!") == 0);
  puts(buffer);

  /* Set io data 2 */
  ret = 2;
  assert(mco_set_io_data(co, &ret, sizeof(ret)) == MCO_SUCCESS);

  /* Nested coroutine test */
  mco_desc desc = mco_desc_init(coro_entry2, 0);
  assert(mco_create(&co2, &desc) == MCO_SUCCESS);
  assert(mco_set_io_data(co2, &co, sizeof(co)) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_resume(co2) == MCO_SUCCESS);
  assert(mco_get_io_data(co2, &co, sizeof(co)) == 0);
  assert(mco_status(co2) == MCO_DEAD);
  assert(mco_status(co) == MCO_RUNNING);
  assert(mco_running() == co);
}

int main(void) {
  mco_coro* co;
  int ret = 0;

  /* Create coroutine */
  mco_desc desc = mco_desc_init(coro_entry, 0);
  desc.user_data = &dummy_user_data;
  assert(mco_create(&co, &desc) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* Set io data 1 */
  const char first_word[] = "hello";
  assert(mco_set_io_data(co, first_word, sizeof(first_word)) == MCO_SUCCESS);

  /* Resume 1 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_SUSPENDED);

  /* Get io data 1 */
  assert(mco_get_io_data(co, &ret, sizeof(ret)) == sizeof(ret));
  assert(ret == 1);

  /* Set io data 2 */
  const char second_word[] = "world!";
  assert(mco_set_io_data(co, second_word, sizeof(second_word)) == MCO_SUCCESS);

  /* Resume 2 */
  assert(mco_resume(co) == MCO_SUCCESS);
  assert(mco_status(co) == MCO_DEAD);

  /* Get io data 2 */
  assert(mco_get_io_data(co, &ret, sizeof(ret)) == sizeof(ret));
  assert(ret == 2);

  /* Destroy */
  assert(mco_destroy(co) == MCO_SUCCESS);
  printf("finished!\n");
  return 0;
}
