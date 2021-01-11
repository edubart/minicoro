# minicoro

Minicoro is single-file library for using asymmetric coroutines in C.
The API is inspired by [Lua coroutines](https://www.lua.org/manual/5.4/manual.html#6.2) but with C use in mind.

The project is being developed mainly to be a coroutine backend
for the [Nelua](https://github.com/edubart/nelua-lang) programming language.

The library assembly implementation is inspired by [Lua Coco](https://coco.luajit.org/index.html) by Mike Pall.

# Features

- Stackful asymmetric coroutines.
- Supports nesting coroutines (resuming a coroutine from another coroutine).
- Supports custom allocators.
- Allow passing values between yield and resume.
- Customizable stack size.
- Coroutine API design inspired by Lua with use C in mind.
- Yield across any C function.
- Made to work in multithread applications.
- Cross platform.
- Minimal, self contained and no external dependencies.
- Readable sources and documented.
- Implemented via assembly, ucontext or fibers.
- Lightweight and efficient.
- Works in any C89 compiler.
- Error prone API, returning proper error codes on misuse.
- Support running with valgrind.

# Implementation details

On Unix systems the context switching is implemented via assembly instructions for
x86/x86_64 and aarch64 architectures otherwise fallbacks to ucontext implementation.
On Windows the context switching is implemented via the Fibers API.

# Limitations

- Don't use coroutines with C++ exceptions, this is not supported.
- When using C++ RAII (i.e. destructors) you must resume the coroutine until it dies to properly execute all destructors.
- To properly use in multithread applications, you must compile with C compiler that supports `thread_local` storage.
- Address sanitizers for C may trigger false warnings when using coroutines.
- The `mco_coro` object is not thread safe, you should lock each coroutine into a thread.

# Usage

To use minicoro, do the following in one .c file:

  ```c
  #define MINICORO_IMPL
  #include "minicoro.h"
  ```

You can do `#include "minicoro.h"` in other parts of the program just like any other header.

## Minimal Example

The following simple example demonstrates on how to use the library:

```c
#define MINICORO_IMPL
#include "minicoro.h"
#include <stdio.h>

// Coroutine entry function.
void coro_entry(mco_coro* co) {
  printf("coroutine 1\n");
  mco_yield(co);
  printf("coroutine 2\n");
}

int main() {
  // First initialize a `mco_desc` object through `mco_desc_init`.
  mco_desc desc = mco_desc_init(coro_entry, 0);
  // Configure desc fields when needed (e.g. customize user_data, stack_size or allocation functions).
  desc.stack_size = 32768;
  // Call `mco_create` with the output coroutine pointer and desc pointer.
  mco_coro* co;
  mco_result res = mco_create(&co, &desc);
  assert(res == MCO_SUCCESS);
  // The coroutine should be now in suspended state.
  assert(mco_status(co) == MCO_SUSPENDED);
  // Call `mco_resume` to start for the first time, switching to its context.
  res = mco_resume(co); // Should print "coroutine 1".
  assert(res == MCO_SUCCESS);
  // We get back from coroutine context in suspended state (because it's unfinished).
  assert(mco_status(co) == MCO_SUSPENDED);
  // Call `mco_resume` to resume for a second time.
  res = mco_resume(co); // Should print "coroutine 2".
  assert(res == MCO_SUCCESS);
  // The coroutine finished and should be now dead.
  assert(mco_status(co) == MCO_DEAD);
  // Call `mco_destroy` to destroy the coroutine.
  res = mco_destroy(co);
  assert(res == MCO_SUCCESS);
  return 0;
}
```

_NOTE_: In case you don't want to use the minicoro allocator system you should
allocate a coroutine object yourself using `mco_desc.coro_size` and call `mco_init`,
then later to destroy call `mco_deinit` and deallocate it.

## Yielding from anywhere

You can yield the current running coroutine from anywhere
without having to pass `mco_coro` pointers around,
to this just use `mco_yield(mco_running())`.

## Passing data between yield and resume

The library has the IO data interface to assist passing data between yield and resume.
It's usage is straightforward,
use `mco_set_io_data` to send data before a `mco_resume` or `mco_yield`,
then later use `mco_get_io_data` after a `mco_resume` or `mco_yield` to receive data.

## Error handling

The library return error codes in most of its API in case of misuse or system error,
the user is encouraged to handle them properly.

## Library customization

The following can be defined to change the library behavior:

- `MCO_API`                   - Public API qualifier. Default is `extern`.
- `MCO_IO_DATA_SIZE`          - Size of IO data interface buffer. Default is 1024.
- `MCO_MIN_STACK_SIZE`        - Minimum stack size when creating a coroutine. Default is 32768.
- `MCO_DEFAULT_STACK_SIZE`    - Default stack size when creating a coroutine. Default is 57344.
- `MCO_MALLOC`                - Default allocation function. Default is `malloc`.
- `MCO_FREE`                  - Default deallocation function. Default is `free`.
- `MCO_DEBUG`                 - Enable debug mode, logging any runtime error to stdout. Defined automatically unless `NDEBUG` or `MCO_NO_DEBUG` is defined.
- `MCO_NO_DEBUG`              - Disable debug mode.
- `MCO_NO_MULTITHREAD`        - Disable multithread usage. Multithread is supported when `thread_local` is supported.
- `MCO_NO_DEFAULT_ALLOCATORS` - Disable the default allocator using `MCO_MALLOC` and `MCO_FREE`.
- `MCO_ZERO_MEMORY`           - Zero memory of stack for new coroutines and when discarding IO data, intended for garbage collected environments.
- `MCO_USE_ASM`               - Force use of assembly context switch implementation.
- `MCO_USE_UCONTEXT`          - Force use ucontext of context switch implementation.
- `MCO_USE_VALGRIND`          - Define if you want run with valgrind to fix accessing memory errors.

# Cheatsheet

Here is a list of all library functions for quick reference:

```c
/* Coroutine functions. */
mco_desc mco_desc_init(mco_func func, uintptr_t stack_size);  /* Initialize description of a coroutine. */
mco_result mco_init(mco_coro* co, mco_desc* desc);            /* Initialize the coroutine. */
mco_result mco_uninit(mco_coro* co);                          /* Uninitialize the coroutine, may fail if it's not dead or suspended. */
mco_result mco_create(mco_coro** out_co, mco_desc* desc);     /* Allocates and initializes a new coroutine. */
mco_result mco_destroy(mco_coro* co);                         /* Uninitialize and deallocate the coroutine, may fail if it's not dead or suspended. */
mco_result mco_resume(mco_coro* co);                          /* Starts or continues the execution of the coroutine. */
mco_result mco_yield(mco_coro* co);                           /* Suspends the execution of a coroutine. */
mco_state mco_status(mco_coro* co);                           /* Returns the status of the coroutine. */
void* mco_get_user_data(mco_coro* co);                        /* Get coroutine user data supplied on coroutine creation. */

/* IO data interface functions. The IO data interface is used to pass values between yield and resume. */
mco_result mco_set_io_data(mco_coro* co, const void* src, size_t len);          /* Set the coroutine IO data. Use to send values between yield and resume. */
mco_result mco_get_io_data(mco_coro* co, void* dest, size_t maxlen);            /* Get the coroutine IO data. Use to receive values between yield and resume. */
size_t mco_get_io_data_size();                                                  /* Get the coroutine IO data size. */
mco_result mco_reset_io_data(mco_coro* co);                                     /* Clear the coroutine IO data. Call this to reset IO data before a yield or resume. */
mco_result mco_get_and_reset_io_data(mco_coro* co, void* dest, size_t maxlen);  /* Shortcut for `mco_get_io_data` + `mco_reset_io_data`. */

/* Misc functions. */
mco_coro* mco_running();                            /* Returns the running coroutine for the current thread. */
const char* mco_result_description(mco_result res); /* Get the description of a result. */

```

# Complete Example

The following is a more complete example, generating fibonacci numbers:

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
  mco_result res = mco_get_io_data(co, &max, sizeof(max));
  if(res != MCO_SUCCESS)
    fail("Failed to retrieve coroutine io data", res);

  while(1) {
    /* Yield the next fibonacci number. */
    mco_set_io_data(co, &m, sizeof(m));
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

  /* Set io data. */
  unsigned long max = 1000000000;
  mco_set_io_data(co, &max, sizeof(max));

  int counter = 1;
  while(mco_status(co) == MCO_SUSPENDED) {
    /* Resume the coroutine. */
    res = mco_resume(co);
    if(res != MCO_SUCCESS)
      fail("Failed to resume coroutine", res);

    /* Retrieve io data set in last coroutine yield. */
    unsigned long ret = 0;
    if(mco_get_io_data(co, &ret, sizeof(ret)) != MCO_SUCCESS)
      fail("Failed to retrieve coroutine io data", res);
    printf("fib %d = %lu\n", counter, ret);
    counter = counter + 1;
  }

  /* Destroy the coroutine. */
  res = mco_destroy(co);
  if(res != MCO_SUCCESS)
    fail("Failed to destroy coroutine", res);
  return 0;
}
```

# Updates

- **10-Jan-2021**: Minor API improvements and document more.
- **09-Jan-2021**: Library created.

# License

MIT license, see LICENSE file for licensing information.
