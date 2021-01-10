# minicoro

Minimal, single-file, one-header, cross-platform, asymmetric stackful coroutine library in pure C.

The API tries to be very similar to [Lua coroutine](https://www.lua.org/manual/5.4/manual.html#6.2)
API but with C in mind.

This is project is being developed mainly to be a coroutine backend
for the [Nelua programming language](https://github.com/edubart/nelua-lang).

# Features

* Stackful asymmetric coroutines
* Support nested coroutines (resuming a coroutine inside another coroutine)
* Allow using custom allocators
* Customizable stack size
* Very Lua like API design
* Pass user data between yield and resume
* Yield across any C function
* Made to work with multiple threads in mind
* Cross platform
* Minimal and readable sources
* Self contained (one header)
* Works in any C99 compiler

# Implementation details

On POSIX it uses `ucontext` API and on Windows it uses the fibers API.
In the future it may use `_setjmp`/`_longjmp` on POSIX system instead of `ucontext`
because it would perform context switching a little faster (no syscalls).

# Limitations

* To properly support multithread you must compile with a C compiler that does support
`_Thread_local` storage.
* The library should work with multiple threads, but the `mco_coro` object is not thread safe.
* When using in C++, the user should avoid using exceptions and RAII inside the coroutine.

# Usage

Copy `minicoro.h` in your project and define `MINICORO_IMPL` before including it in one C file.

# Documentation

Read the top of `minicoro.h` for usage information and API.

# Example Usage

```c
#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>

static void fail(const char* message, mco_result res) {
  printf("%s: %s", message, mco_result_description(res));
  exit(-1);
}

static void fibonacci_coro(mco_coro* co) {
  unsigned long m = 1;
  unsigned long n = 1;

  /* Retrieve max value. */
  unsigned long max;
  mco_result res = mco_get_user_data(co, &max, sizeof(max));
  if(res != MCO_SUCCESS)
    fail("Failed to retrieve coroutine user data", res);

  while(1) {
    /* Yield the next fibonacci number. */
    mco_set_user_data(co, &m, sizeof(m));
    res = mco_yield(co);
    if(res != MCO_SUCCESS)
      fail("Failed to yield coroutine", res);

    unsigned long tmp = m + n;
    m = n;
    n = tmp;
    if(m >= max)
      break;
  }
}

int main() {
  /* Create the coroutine. */
  mco_coro* co;
  mco_desc desc = mco_desc_init(fibonacci_coro, 0);
  mco_result res = mco_create(&co, &desc);
  if(res != MCO_SUCCESS)
    fail("Failed to create coroutine", res);

  /* Set user data. */
  unsigned long max = 1000000000;
  mco_set_user_data(co, &max, sizeof(max));


  int counter = 1;
  while(mco_status(co) == MCO_SUSPENDED) {
    /* Resume the coroutine. */
    res = mco_resume(co);
    if(res != MCO_SUCCESS)
      fail("Failed to resume coroutine", res);

    /* Retrieve user data set in last coroutine yield. */
    unsigned long ret = 0;
    if(mco_get_user_data(co, &ret, sizeof(ret)) != MCO_SUCCESS)
      fail("Failed to retrieve coroutine user data", res);
    printf("fib %d = %lu\n", counter, ret);
    counter = counter + 1;
  }

  /* Destroy the coroutine. */
  res = mco_destroy(co);
  return 0;
}
```

# Updates

- **09-Jan-2021**: Library created.

# License

MIT license, see LICENSE file for licensing information.
