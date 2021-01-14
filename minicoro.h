/*
Minimal asymmetric stackful cross-platform coroutine library in pure C.
minicoro
Eduardo Bart - edub4rt@gmail.com
https://github.com/edubart/minicoro

Minicoro is single file library for using asymmetric coroutines in C.
The API is inspired by Lua coroutines but with C use in mind.

# Features

- Stackful asymmetric coroutines.
- Supports nesting coroutines (resuming a coroutine from another coroutine).
- Supports custom allocators.
- Storage system to allow passing values between yield and resume.
- Customizable stack size.
- Coroutine API design inspired by Lua with C use in mind.
- Yield across any C function.
- Made to work in multithread applications.
- Cross platform.
- Minimal, self contained and no external dependencies.
- Readable sources and documented.
- Implemented via assembly, ucontext or fibers.
- Lightweight and efficient.
- Works in most C89 compilers.
- Error prone API, returning proper error codes on misuse.
- Support running with valgrind.
- Support running with ASan (AddressSanitizer) and TSan (ThreadSanitizer).

# Implementation details

Most platforms are supported through different methods.

| Architecture | System      | Method    |
|--------------|-------------|-----------|
| x86_32       | (any OS)    | GCC asm   |
| x86_64       | (any OS)    | GCC asm   |
| ARM          | (any OS)    | GCC asm   |
| ARM64        | (any OS)    | GCC asm   |
| (any CPU)    | (any OS)    | ucontext  |
| (any CPU)    | Windows     | fibers    |
| x86_64       | Windows     | blob asm  |
| WebAssembly  | Web         | fibers    |

The ucontext method is used as a fallback if the compiler or CPU does not support GCC inline assembly.
The fibers method is the default on Windows, to use the assembly method you have to explicitly enable it.

# Caveats

- Don't use coroutines with C++ exceptions, this is not supported.
- When using C++ RAII (i.e. destructors) you must resume the coroutine until it dies to properly execute all destructors.
- To use in multithread applications, you must compile with C compiler that supports `thread_local` qualifier.
- Some unsupported sanitizers for C may trigger false warnings when using coroutines.
- The `mco_coro` object is not thread safe, you should lock each coroutine into a thread.
- Take care to not cause stack overflows, otherwise your program may crash or not, the behavior is undefined.
- Some older operating systems may have defective ucontext implementations because this feature is not widely used, upgrade your OS.
- On WebAssembly you must compile with emscripten flag `-s ASYNCIFY=1`.

# Introduction

A coroutine represents an independent "green" thread of execution.
Unlike threads in multithread systems, however,
a coroutine only suspends its execution by explicitly calling a yield function.

You create a coroutine by calling `mco_create`.
Its sole argument is a `mco_desc` structure with a description for the coroutine.
The `mco_create` function only creates a new coroutine and returns a handle to it, it does not start the coroutine.

You execute a coroutine by calling `mco_resume`.
When calling a resume function the coroutine starts its execution by calling its body function.
After the coroutine starts running, it runs until it terminates or yields.

A coroutine yields by calling `mco_yield`.
When a coroutine yields, the corresponding resume returns immediately,
even if the yield happens inside nested function calls (that is, not in the main function).
The next time you resume the same coroutine, it continues its execution from the point where it yielded.

To associate a persistent value with the coroutine,
you can  optionally set `user_data` on its creation and later retrieve with `mco_get_user_data`.

To pass values between resume and yield,
you can optionally use `mco_set_storage` and `mco_get_storage` APIs,
they are intended to pass temporary values.

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
  // First initialize a `desc` object through `mco_desc_init`.
  mco_desc desc = mco_desc_init(coro_entry, 0);
  // Configure `desc` fields when needed (e.g. customize user_data, stack_size or allocation functions).
  desc.stack_size = 32768;
  // Call `mco_create` with the output coroutine pointer and `desc` pointer.
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

The library has the storage interface to assist passing data between yield and resume.
It's usage is straightforward,
use `mco_set_storage` to send data before a `mco_resume` or `mco_yield`,
then later use `mco_get_storage` after a `mco_resume` or `mco_yield` to receive data.

## Error handling

The library return error codes in most of its API in case of misuse or system error,
the user is encouraged to handle them properly.

## Library customization

The following can be defined to change the library behavior:

- `MCO_API`                   - Public API qualifier. Default is `extern`.
- `MCO_MIN_STACK_SIZE`        - Minimum stack size when creating a coroutine. Default is 32768.
- `MCO_DEFAULT_STORAGE_SIZE`  - Size of coroutine storage buffer. Default is 1024.
- `MCO_DEFAULT_STACK_SIZE`    - Default stack size when creating a coroutine. Default is 57344.
- `MCO_MALLOC`                - Default allocation function. Default is `malloc`.
- `MCO_FREE`                  - Default deallocation function. Default is `free`.
- `MCO_DEBUG`                 - Enable debug mode, logging any runtime error to stdout. Defined automatically unless `NDEBUG` or `MCO_NO_DEBUG` is defined.
- `MCO_NO_DEBUG`              - Disable debug mode.
- `MCO_NO_MULTITHREAD`        - Disable multithread usage. Multithread is supported when `thread_local` is supported.
- `MCO_NO_DEFAULT_ALLOCATORS` - Disable the default allocator using `MCO_MALLOC` and `MCO_FREE`.
- `MCO_ZERO_MEMORY`           - Zero memory of stack for new coroutines and when discarding storage, intended for garbage collected environments.
- `MCO_USE_ASM`               - Force use of assembly context switch implementation.
- `MCO_USE_UCONTEXT`          - Force use of ucontext context switch implementation.
- `MCO_USE_FIBERS`            - Force use of fibers context switch implementation.
- `MCO_USE_VALGRIND`          - Define if you want run with valgrind to fix accessing memory errors.

# License

Your choice of either Public Domain or MIT No Attribution, see end of file.
*/


#ifndef MINICORO_H
#define MINICORO_H

#ifdef __cplusplus
extern "C" {
#endif

/* Public API qualifier. */
#ifndef MCO_API
#define MCO_API extern
#endif

/* Size of coroutine storage buffer. */
#ifndef MCO_DEFAULT_STORAGE_SIZE
#define MCO_DEFAULT_STORAGE_SIZE 1024
#endif

#include <stddef.h> /* for size_t */

/* ---------------------------------------------------------------------------------------------- */

/* Coroutine states. */
typedef enum mco_state {
  MCO_DEAD = 0,  /* The coroutine has finished normally or was uninitialized before finishing. */
  MCO_NORMAL,    /* The coroutine is active but not running (that is, it has resumed another coroutine). */
  MCO_RUNNING,   /* The coroutine is active and running. */
  MCO_SUSPENDED, /* The coroutine is suspended (in a call to yield, or it has not started running yet). */
} mco_state;

/* Coroutine result codes. */
typedef enum mco_result {
  MCO_SUCCESS = 0,
  MCO_GENERIC_ERROR,
  MCO_INVALID_POINTER,
  MCO_INVALID_COROUTINE,
  MCO_NOT_SUSPENDED,
  MCO_NOT_RUNNING,
  MCO_MAKE_CONTEXT_ERROR,
  MCO_SWITCH_CONTEXT_ERROR,
  MCO_NOT_ENOUGH_SPACE,
  MCO_OUT_OF_MEMORY,
  MCO_INVALID_ARGUMENTS,
  MCO_INVALID_OPERATION,
} mco_result;

/* Coroutine structure. */
typedef struct mco_coro mco_coro;
struct mco_coro {
  void* context;
  mco_state state;
  void (*func)(mco_coro* co);
  mco_coro* prev_co;
  void* user_data;
  void* allocator_data;
  void (*free_cb)(void* ptr, void* allocator_data);
  void* stack_base; /* Stack base address, can be used to scan memory in a garbage collector. */
  size_t stack_size;
  unsigned char* storage;
  size_t storage_available_size;
  size_t storage_size;
  void* asan_prev_stack; /* Used by address sanitizer. */
  void* tsan_prev_fiber; /* Used by thread sanitizer. */
  void* tsan_fiber; /* Used by thread sanitizer. */
};

/* Structure used to initialize a coroutine. */
typedef struct mco_desc {
  void (*func)(mco_coro* co); /* Entry point function for the coroutine. */
  void* user_data;            /* Coroutine user data, can be get with `mco_get_user_data`. */
  /* Custom allocation interface. */
  void* (*malloc_cb)(size_t size, void* allocator_data); /* Custom allocation function. */
  void  (*free_cb)(void* ptr, void* allocator_data);     /* Custom deallocation function. */
  void* allocator_data;       /* User data pointer passed to `malloc`/`free` allocation functions. */
  size_t storage_size;        /* Coroutine storage size, to be used with the storage APIs. */
  /* These must be initialized only through `mco_init_desc`. */
  size_t coro_size;           /* Coroutine structure size. */
  size_t stack_size;          /* Coroutine stack size. */
} mco_desc;

/* Coroutine functions. */
MCO_API mco_desc mco_desc_init(void (*func)(mco_coro* co), size_t stack_size);  /* Initialize description of a coroutine. When stack size is 0 then MCO_DEFAULT_STACK_SIZE is be used. */
MCO_API mco_result mco_init(mco_coro* co, mco_desc* desc);                      /* Initialize the coroutine. */
MCO_API mco_result mco_uninit(mco_coro* co);                                    /* Uninitialize the coroutine, may fail if it's not dead or suspended. */
MCO_API mco_result mco_create(mco_coro** out_co, mco_desc* desc);               /* Allocates and initializes a new coroutine. */
MCO_API mco_result mco_destroy(mco_coro* co);                                   /* Uninitialize and deallocate the coroutine, may fail if it's not dead or suspended. */
MCO_API mco_result mco_resume(mco_coro* co);                                    /* Starts or continues the execution of the coroutine. */
MCO_API mco_result mco_yield(mco_coro* co);                                     /* Suspends the execution of a coroutine. */
MCO_API mco_state mco_status(mco_coro* co);                                     /* Returns the status of the coroutine. */
MCO_API void* mco_get_user_data(mco_coro* co);                                  /* Get coroutine user data supplied on coroutine creation. */

/* Storage interface functions, used to pass values between yield and resume. */
MCO_API mco_result mco_set_storage(mco_coro* co, const void* src, size_t len);  /* Set the coroutine storage. Use to send values between yield and resume. */
MCO_API mco_result mco_reset_storage(mco_coro* co);                             /* Clear the coroutine storage. Call this to reset storage before a yield or resume. */
MCO_API mco_result mco_get_storage(mco_coro* co, void* dest, size_t len);       /* Get the coroutine storage. Use to receive values between yield and resume. */
MCO_API size_t mco_get_storage_available_size(mco_coro* co);                    /* Get the available storage size to retrieve with `mco_get_storage`. */
MCO_API size_t mco_get_storage_size(mco_coro* co);                              /* Get the coroutine storage size. */
MCO_API void* mco_get_storage_pointer(mco_coro* co);                            /* Get the coroutine storage pointer. Use only if you do not wish to use the set/get methods. */

/* Misc functions. */
MCO_API mco_coro* mco_running(void);                        /* Returns the running coroutine for the current thread. */
MCO_API const char* mco_result_description(mco_result res); /* Get the description of a result. */

#ifdef __cplusplus
}
#endif

#endif /* MINICORO_H */

#ifdef MINICORO_IMPL

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------------------------- */

/* Minimum stack size when creating a coroutine. */
#ifndef MCO_MIN_STACK_SIZE
#define MCO_MIN_STACK_SIZE 32768
#endif

/* Default stack size when creating a coroutine. */
#ifndef MCO_DEFAULT_STACK_SIZE
#define MCO_DEFAULT_STACK_SIZE 57344 /* Don't use multiples of 64K to avoid D-cache aliasing conflicts. */
#endif

/* Detect implementation based on OS, arch and compiler. */
#if !defined(MCO_USE_UCONTEXT) && !defined(MCO_USE_FIBERS) && !defined(MCO_USE_ASM)
  #if defined(_WIN32) || defined(__EMSCRIPTEN__)
    #define MCO_USE_FIBERS
  #else
    #if __GNUC__ >= 3 /* Assembly extension supported. */
      #if defined(__x86_64__) || defined(__i386) || defined(__i386__) || defined(__ARM_EABI__) || defined(__aarch64__)
        #define MCO_USE_ASM
      #else
        #define MCO_USE_UCONTEXT
      #endif
    #else
      #define MCO_USE_UCONTEXT
    #endif
  #endif
#endif

#define _MCO_UNUSED(x) (void)(x)

#if !defined(MCO_NO_DEBUG) && !defined(NDEBUG) && !defined(MCO_DEBUG)
#define MCO_DEBUG
#endif

#ifndef MCO_LOG
  #ifdef MCO_DEBUG
    #include <stdio.h>
    #define MCO_LOG(s) puts(s)
  #else
    #define MCO_LOG(s)
  #endif
#endif

#ifndef MCO_ASSERT
  #ifdef MCO_DEBUG
    #include <assert.h>
    #define MCO_ASSERT(c) assert(c)
  #else
    #define MCO_ASSERT(c)
  #endif
#endif

#ifndef MCO_THREAD_LOCAL
  #ifdef MCO_NO_MULTITHREAD
    #define MCO_THREAD_LOCAL
  #else
    #ifdef thread_local
      #define MCO_THREAD_LOCAL thread_local
    #elif __STDC_VERSION__ >= 201112 && !defined(__STDC_NO_THREADS__)
      #define MCO_THREAD_LOCAL _Thread_local
    #elif defined(_WIN32) && (defined(_MSC_VER) || defined(__ICL) ||  defined(__DMC__) ||  defined(__BORLANDC__))
      #define MCO_THREAD_LOCAL __declspec(thread)
    #elif defined(__GNUC__) || defined(__SUNPRO_C) || defined(__xlC__)
      #define MCO_THREAD_LOCAL __thread
    #else /* No thread local support, `mco_running` will be thread unsafe. */
      #define MCO_THREAD_LOCAL
      #define MCO_NO_MULTITHREAD
    #endif
  #endif
#endif

#ifndef MCO_FORCE_INLINE
  #ifdef _MSC_VER
    #define MCO_FORCE_INLINE __forceinline
  #elif defined(__GNUC__)
    #if defined(__STRICT_ANSI__)
      #define MCO_FORCE_INLINE __inline__ __attribute__((always_inline))
    #else
      #define MCO_FORCE_INLINE inline __attribute__((always_inline))
    #endif
  #elif defined(__BORLANDC__) || defined(__DMC__) || defined(__SC__) || defined(__WATCOMC__) || defined(__LCC__) ||  defined(__DECC)
    #define MCO_FORCE_INLINE __inline
  #else /* No inline support. */
    #define MCO_FORCE_INLINE
  #endif
#endif

#ifndef MCO_NO_DEFAULT_ALLOCATORS
#ifndef MCO_MALLOC
  #include <stdlib.h>
  #define MCO_MALLOC malloc
  #define MCO_FREE free
#endif
static void* mco_malloc(size_t size, void* allocator_data) {
  _MCO_UNUSED(allocator_data);
  return MCO_MALLOC(size);
}
static void mco_free(void* ptr, void* allocator_data) {
  _MCO_UNUSED(allocator_data);
  MCO_FREE(ptr);
}
#endif /* MCO_NO_DEFAULT_ALLOCATORS */

#if defined(__has_feature)
  #if __has_feature(address_sanitizer)
    #define _MCO_USE_ASAN
  #endif
  #if __has_feature(thread_sanitizer)
    #define _MCO_USE_TSAN
  #endif
#endif
#if defined(__SANITIZE_ADDRESS__)
  #define _MCO_USE_ASAN
#endif
#if defined(__SANITIZE_THREAD__)
  #define _MCO_USE_TSAN
#endif
#ifdef _MCO_USE_ASAN
void __sanitizer_start_switch_fiber(void** fake_stack_save, const void *bottom, size_t size);
void __sanitizer_finish_switch_fiber(void* fake_stack_save, const void **bottom_old, size_t *size_old);
#endif
#ifdef _MCO_USE_TSAN
void* __tsan_get_current_fiber(void);
void* __tsan_create_fiber(unsigned flags);
void __tsan_destroy_fiber(void* fiber);
void __tsan_switch_to_fiber(void* fiber, unsigned flags);
#endif

#include <string.h> /* For memcpy and memset. */

/* Utility for aligning addresses. */
static MCO_FORCE_INLINE size_t _mco_align_forward(size_t addr, size_t align) {
  return (addr + (align-1)) & ~(align-1);
}

/* Variable holding the current running coroutine per thread. */
static MCO_THREAD_LOCAL mco_coro* mco_current_co = NULL;

static MCO_FORCE_INLINE void _mco_prepare_jumpin(mco_coro* co) {
  /* Set the old coroutine to normal state and update it. */
  mco_coro* prev_co = mco_running(); /* Must access through `mco_running`. */
  MCO_ASSERT(co->prev_co == NULL);
  co->prev_co = prev_co;
  if(prev_co) {
    MCO_ASSERT(prev_co->state == MCO_RUNNING);
    prev_co->state = MCO_NORMAL;
  }
  mco_current_co = co;
#ifdef _MCO_USE_ASAN
  if(prev_co) {
    void* bottom_old = NULL;
    size_t size_old = 0;
    __sanitizer_finish_switch_fiber(prev_co->asan_prev_stack, (const void**)&bottom_old, &size_old);
    prev_co->asan_prev_stack = NULL;
  }
  __sanitizer_start_switch_fiber(&co->asan_prev_stack, co->stack_base, co->stack_size);
#endif
#ifdef _MCO_USE_TSAN
  co->tsan_prev_fiber = __tsan_get_current_fiber();
  __tsan_switch_to_fiber(co->tsan_fiber, 0);
#endif
}

static MCO_FORCE_INLINE void _mco_prepare_jumpout(mco_coro* co) {
  /* Switch back to the previous running coroutine. */
  MCO_ASSERT(mco_running() == co);
  mco_coro* prev_co = co->prev_co;
  co->prev_co = NULL;
  if(prev_co) {
    MCO_ASSERT(prev_co->state == MCO_NORMAL);
    prev_co->state = MCO_RUNNING;
  }
  mco_current_co = prev_co;
#ifdef _MCO_USE_ASAN
  void* bottom_old = NULL;
  size_t size_old = 0;
  __sanitizer_finish_switch_fiber(co->asan_prev_stack, (const void**)&bottom_old, &size_old);
  co->asan_prev_stack = NULL;
  if(prev_co) {
    __sanitizer_start_switch_fiber(&prev_co->asan_prev_stack, bottom_old, size_old);
  }
#endif
#ifdef _MCO_USE_TSAN
  void* tsan_prev_fiber = co->tsan_prev_fiber;
  co->tsan_prev_fiber = NULL;
  __tsan_switch_to_fiber(tsan_prev_fiber, 0);
#endif
}

static void _mco_jumpin(mco_coro* co);
static void _mco_jumpout(mco_coro* co);

static void _mco_main(mco_coro* co) {
  co->func(co); /* Run the coroutine function. */
  co->state = MCO_DEAD; /* Coroutine finished successfully, set state to dead. */
  _mco_jumpout(co); /* Jump back to the old context .*/
}

/* ---------------------------------------------------------------------------------------------- */

#if defined(MCO_USE_UCONTEXT) || defined(MCO_USE_ASM)

#ifdef MCO_USE_ASM

#if defined(__x86_64__)

#ifdef _WIN32

typedef struct _mco_ctxbuf {
  void* buf[10]; /* rip, rsp, rbp, rbx, r12, r13, r14, r15, rdi, rsi */
  void* xmm[10*2]; /* xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15 */
} _mco_ctxbuf;

#ifdef __GNUC__
#define _MCO_ASM_BLOB __attribute__((section(".text#")))
#elif defined(_MSC_VER)
#define _MCO_ASM_BLOB __declspec(allocate(".text"))
#pragma section(".text")
#endif

_MCO_ASM_BLOB static unsigned char _mco_wrap_main_code[] = {
  0x4c, 0x89, 0xe9,          /* mov    %r13,%rcx */
  0x41, 0xff, 0xe4,          /* jmpq   *%r12 */
  0xc3,                      /* retq */
};

_MCO_ASM_BLOB static unsigned char _mco_switch_code[] = {
  0x48, 0x8d, 0x05, 0xeb, 0x00, 0x00, 0x00,             /* lea    0xeb(%rip),%rax */
  0x48, 0x89, 0x01,                                     /* mov    %rax,(%rcx) */
  0x48, 0x89, 0x61, 0x08,                               /* mov    %rsp,0x8(%rcx) */
  0x48, 0x89, 0x69, 0x10,                               /* mov    %rbp,0x10(%rcx) */
  0x48, 0x89, 0x59, 0x18,                               /* mov    %rbx,0x18(%rcx) */
  0x4c, 0x89, 0x61, 0x20,                               /* mov    %r12,0x20(%rcx) */
  0x4c, 0x89, 0x69, 0x28,                               /* mov    %r13,0x28(%rcx) */
  0x4c, 0x89, 0x71, 0x30,                               /* mov    %r14,0x30(%rcx) */
  0x4c, 0x89, 0x79, 0x38,                               /* mov    %r15,0x38(%rcx) */
  0x48, 0x89, 0x79, 0x40,                               /* mov    %rdi,0x40(%rcx) */
  0x48, 0x89, 0x71, 0x48,                               /* mov    %rsi,0x48(%rcx) */
  0x66, 0x0f, 0xd6, 0x71, 0x50,                         /* movq   %xmm6,0x50(%rcx) */
  0x66, 0x0f, 0xd6, 0x79, 0x60,                         /* movq   %xmm7,0x60(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0x41, 0x70,                   /* movq   %xmm8,0x70(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0x89, 0x80, 0x00, 0x00, 0x00, /* movq   %xmm9,0x80(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0x91, 0x90, 0x00, 0x00, 0x00, /* movq   %xmm10,0x90(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0x99, 0xa0, 0x00, 0x00, 0x00, /* movq   %xmm11,0xa0(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0xa1, 0xb0, 0x00, 0x00, 0x00, /* movq   %xmm12,0xb0(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0xa9, 0xc0, 0x00, 0x00, 0x00, /* movq   %xmm13,0xc0(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0xb1, 0xd0, 0x00, 0x00, 0x00, /* movq   %xmm14,0xd0(%rcx) */
  0x66, 0x44, 0x0f, 0xd6, 0xb9, 0xe0, 0x00, 0x00, 0x00, /* movq   %xmm15,0xe0(%rcx) */
  0xf3, 0x44, 0x0f, 0x7e, 0xba, 0xe0, 0x00, 0x00, 0x00, /* movq   0xe0(%rdx),%xmm15 */
  0xf3, 0x44, 0x0f, 0x7e, 0xb2, 0xd0, 0x00, 0x00, 0x00, /* movq   0xd0(%rdx),%xmm14 */
  0xf3, 0x44, 0x0f, 0x7e, 0xaa, 0xc0, 0x00, 0x00, 0x00, /* movq   0xc0(%rdx),%xmm13 */
  0xf3, 0x44, 0x0f, 0x7e, 0xa2, 0xb0, 0x00, 0x00, 0x00, /* movq   0xb0(%rdx),%xmm12 */
  0xf3, 0x44, 0x0f, 0x7e, 0x9a, 0xa0, 0x00, 0x00, 0x00, /* movq   0xa0(%rdx),%xmm11 */
  0xf3, 0x44, 0x0f, 0x7e, 0x92, 0x90, 0x00, 0x00, 0x00, /* movq   0x90(%rdx),%xmm10 */
  0xf3, 0x44, 0x0f, 0x7e, 0x8a, 0x80, 0x00, 0x00, 0x00, /* movq   0x80(%rdx),%xmm9 */
  0xf3, 0x44, 0x0f, 0x7e, 0x42, 0x70,                   /* movq   0x70(%rdx),%xmm8 */
  0xf3, 0x0f, 0x7e, 0x7a, 0x60,                         /* movq   0x60(%rdx),%xmm7 */
  0xf3, 0x0f, 0x7e, 0x72, 0x50,                         /* movq   0x50(%rdx),%xmm6 */
  0x48, 0x8b, 0x72, 0x48,                               /* mov    0x48(%rdx),%rsi */
  0x48, 0x8b, 0x7a, 0x40,                               /* mov    0x40(%rdx),%rdi */
  0x4c, 0x8b, 0x7a, 0x38,                               /* mov    0x38(%rdx),%r15 */
  0x4c, 0x8b, 0x72, 0x30,                               /* mov    0x30(%rdx),%r14 */
  0x4c, 0x8b, 0x6a, 0x28,                               /* mov    0x28(%rdx),%r13 */
  0x4c, 0x8b, 0x62, 0x20,                               /* mov    0x20(%rdx),%r12 */
  0x48, 0x8b, 0x5a, 0x18,                               /* mov    0x18(%rdx),%rbx */
  0x48, 0x8b, 0x6a, 0x10,                               /* mov    0x10(%rdx),%rbp */
  0x48, 0x8b, 0x62, 0x08,                               /* mov    0x8(%rdx),%rsp */
  0xff, 0x22,                                           /* jmpq   *(%rdx) */
  0xc3,                                                 /* retq */
};

void (*_mco_wrap_main)(void) = (void(*)(void))(void*)_mco_wrap_main_code;
void (*_mco_switch)(_mco_ctxbuf* from, _mco_ctxbuf* to) = (void(*)(_mco_ctxbuf* from, _mco_ctxbuf* to))(void*)_mco_switch_code;

#else /* _WIN32 */

typedef struct _mco_ctxbuf {
  void* buf[8]; /* rip, rsp, rbp, rbx, r12, r13, r14, r15 */
} _mco_ctxbuf;

static void _mco_wrap_main(void) {
  __asm__ __volatile__ (
    "movq %r13, %rdi\n\t"
    "jmpq *%r12");
}

static MCO_FORCE_INLINE void _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to) {
  __asm__ __volatile__ (
    "leaq 1f(%%rip), %%rax\n\t"
    "movq %%rax, (%0)\n\t"
    "movq %%rsp, 8(%0)\n\t"
    "movq %%rbp, 16(%0)\n\t"
    "movq %%rbx, 24(%0)\n\t"
    "movq %%r12, 32(%0)\n\t"
    "movq %%r13, 40(%0)\n\t"
    "movq %%r14, 48(%0)\n\t"
    "movq %%r15, 56(%0)\n\t"
    "movq 56(%1), %%r15\n\t"
    "movq 48(%1), %%r14\n\t"
    "movq 40(%1), %%r13\n\t"
    "movq 32(%1), %%r12\n\t"
    "movq 24(%1), %%rbx\n\t"
    "movq 16(%1), %%rbp\n\t"
    "movq 8(%1), %%rsp\n\t"
    "jmpq *(%1)\n"
    "1:\n"
    : "+S" (from), "+D" (to) :
    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc");
}

#endif /* else _WIN32 */

static mco_result _mco_makectx(mco_coro* co, _mco_ctxbuf* ctx, void* stack_base, size_t stack_size) {
#ifndef _WIN32
  /* Reserve 128 bytes for the Red Zone space (System V AMD64 ABI). */
  stack_size = stack_size - 128;
#endif
  void** stack_high_ptr = (void**)((size_t)stack_base + stack_size - sizeof(size_t));
  stack_high_ptr[0] = (void*)(0xdeaddeaddeaddead);  /* Dummy return address. */
  ctx->buf[0] = (void*)(_mco_wrap_main);
  ctx->buf[1] = (void*)(stack_high_ptr);
  ctx->buf[4] = (void*)(_mco_main);
  ctx->buf[5] = (void*)(co);
  return MCO_SUCCESS;
}

#elif defined(__i386) || defined(__i386__)

#ifdef __PIC__
typedef struct _mco_ctxbuf {
  void* buf[4]; /* eip, esp, ebp, ebx */
} _mco_ctxbuf;
static MCO_FORCE_INLINE void _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to) {
  __asm__ __volatile__ (
    "call 1f\n"
    "1:\tpopl %%eax\n\t"
    "addl $(2f-1b),%%eax\n\t"
    "movl %%eax, (%0)\n\t"
    "movl %%esp, 4(%0)\n\t"
    "movl %%ebp, 8(%0)\n\t"
    "movl %%ebx, 12(%0)\n\t"
    "movl 12(%1), %%ebx\n\t"
    "movl 8(%1), %%ebp\n\t"
    "movl 4(%1), %%esp\n\t"
    "jmp *(%1)\n"
    "2:\n"
    : "+S" (from), "+D" (to) : : "eax", "ecx", "edx", "memory", "cc");
}
#else
typedef struct _mco_ctxbuf {
  void* buf[3]; /* eip, esp, ebp */
} _mco_ctxbuf;
static MCO_FORCE_INLINE void _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to) {
  __asm__ __volatile__ (
    "movl $1f, (%0)\n\t"
    "movl %%esp, 4(%0)\n\t"
    "movl %%ebp, 8(%0)\n\t"
    "movl 8(%1), %%ebp\n\t"
    "movl 4(%1), %%esp\n\t"
    "jmp *(%1)\n"
    "1:\n"
    : "+S" (from), "+D" (to) : : "eax", "ebx", "ecx", "edx", "memory", "cc");
}
#endif /* __PIC__ */

static mco_result _mco_makectx(mco_coro* co, _mco_ctxbuf* ctx, void* stack_base, size_t stack_size) {
  void** stack_high_ptr = (void**)((size_t)stack_base + stack_size - 16 - 1*sizeof(size_t));
  stack_high_ptr[0] = (void*)(0xdeaddead);  /* Dummy return address. */
  stack_high_ptr[1] = (void*)(co);
  ctx->buf[0] = (void*)(_mco_main);
  ctx->buf[1] = (void*)(stack_high_ptr);
  return MCO_SUCCESS;
}

#elif defined(__ARM_EABI__)

#if __SOFTFP__
#define _MCO_FLOAT_SAVE   0
#else
#define _MCO_FLOAT_SAVE   16
#endif

typedef struct _mco_ctxbuf {
  void* buf[_MCO_FLOAT_SAVE + 10]; /* [d8-d15,] r4-r11, lr, sp */
} _mco_ctxbuf;

void _mco_wrap_main(void);
int _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to);

__asm__(
  ".text\n"
  ".globl _mco_switch\n"
  ".type _mco_switch #function\n"
  ".hidden _mco_switch\n"
  "_mco_switch:\n"
#if _MCO_FLOAT_SAVE
  "  vstmia r0!, {d8-d15}\n"
#endif
  "  stmia r0, {r4-r11, lr}\n"
  "  str sp, [r0, #9*4]\n"
#if _MCO_FLOAT_SAVE
  "  vldmia r1!, {d8-d15}\n"
#endif
  "  ldr sp, [r1, #9*4]\n"
  "  ldmia r1, {r4-r11, pc}\n"
  ".size _mco_switch, .-_mco_switch\n"
);

__asm__(
  ".text\n"
  ".globl _mco_wrap_main\n"
  ".type _mco_wrap_main #function\n"
  ".hidden _mco_wrap_main\n"
  "_mco_wrap_main:\n"
  "  mov r0, r4\n"
  "  mov ip, r5\n"
  "  mov lr, r6\n"
  "  bx ip\n"
  ".size _mco_wrap_main, .-_mco_wrap_main\n"
);

static mco_result _mco_makectx(mco_coro* co, _mco_ctxbuf* ctx, void* stack_base, size_t stack_size) {
  void** stack_high_ptr = (void**)((size_t)stack_base + stack_size);
  ctx->buf[_MCO_FLOAT_SAVE+0] = (void*)(co);
  ctx->buf[_MCO_FLOAT_SAVE+1] = (void*)(_mco_main);
  ctx->buf[_MCO_FLOAT_SAVE+2] = (void*)(0xdeaddead); /* Dummy return address. */
  ctx->buf[_MCO_FLOAT_SAVE+8] = (void*)(_mco_wrap_main);
  ctx->buf[_MCO_FLOAT_SAVE+9] = stack_high_ptr;
  return MCO_SUCCESS;
}

#elif defined(__aarch64__)

typedef struct _mco_ctxbuf {
  void* buf[22]; /* x19-x30, sp, lr, d8-d15 */
} _mco_ctxbuf;

void _mco_wrap_main(void);
int _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to);

__asm__(
  ".text\n"
  ".globl _mco_switch\n"
  ".type _mco_switch #function\n"
  ".hidden _mco_switch\n"
  "_mco_switch:\n"
  "  mov x10, sp\n"
  "  mov x11, x30\n"
  "  stp x19, x20, [x0, #(0*16)]\n"
  "  stp x21, x22, [x0, #(1*16)]\n"
  "  stp d8, d9, [x0, #(7*16)]\n"
  "  stp x23, x24, [x0, #(2*16)]\n"
  "  stp d10, d11, [x0, #(8*16)]\n"
  "  stp x25, x26, [x0, #(3*16)]\n"
  "  stp d12, d13, [x0, #(9*16)]\n"
  "  stp x27, x28, [x0, #(4*16)]\n"
  "  stp d14, d15, [x0, #(10*16)]\n"
  "  stp x29, x30, [x0, #(5*16)]\n"
  "  stp x10, x11, [x0, #(6*16)]\n"
  "  ldp x19, x20, [x1, #(0*16)]\n"
  "  ldp x21, x22, [x1, #(1*16)]\n"
  "  ldp d8, d9, [x1, #(7*16)]\n"
  "  ldp x23, x24, [x1, #(2*16)]\n"
  "  ldp d10, d11, [x1, #(8*16)]\n"
  "  ldp x25, x26, [x1, #(3*16)]\n"
  "  ldp d12, d13, [x1, #(9*16)]\n"
  "  ldp x27, x28, [x1, #(4*16)]\n"
  "  ldp d14, d15, [x1, #(10*16)]\n"
  "  ldp x29, x30, [x1, #(5*16)]\n"
  "  ldp x10, x11, [x1, #(6*16)]\n"
  "  mov sp, x10\n"
  "  br x11\n"
  ".size _mco_switch, .-_mco_switch\n"
);

__asm__(
  ".text\n"
  ".globl _mco_wrap_main\n"
  ".type _mco_wrap_main #function\n"
  ".hidden _mco_wrap_main\n"
  "_mco_wrap_main:\n"
  "  mov x0, x19\n"
  "  mov x30, x21\n"
  "  br x20\n"
  ".size _mco_wrap_main, .-_mco_wrap_main\n"
);

static mco_result _mco_makectx(mco_coro* co, _mco_ctxbuf* ctx, void* stack_base, size_t stack_size) {
  void** stack_high_ptr = (void**)((size_t)stack_base + stack_size);
  ctx->buf[0] = (void*)(co);
  ctx->buf[1] = (void*)(_mco_main);
  ctx->buf[2] = (void*)(0xdeaddeaddeaddead); /* Dummy return address. */
  ctx->buf[12] = (void*)((size_t)(stack_high_ptr) & ~15);
  ctx->buf[13] = (void*)(_mco_wrap_main);
  return MCO_SUCCESS;
}

#else

#error "Unsupported architecture for assembly method."

#endif /* ARCH */

#elif defined(MCO_USE_UCONTEXT)

#include <ucontext.h>

typedef ucontext_t _mco_ctxbuf;

#if defined(_LP64) || defined(__LP64__)
static void _mco_wrap_main(unsigned int lo, unsigned int hi) {
  mco_coro* co = (mco_coro*)(((size_t)lo) | (((size_t)hi) << 32)); /* Extract coroutine pointer. */
  _mco_main(co);
}
#else
static void _mco_wrap_main(unsigned int lo) {
  mco_coro* co = (mco_coro*)((size_t)lo); /* Extract coroutine pointer. */
  _mco_main(co);
}
#endif

static MCO_FORCE_INLINE void _mco_switch(_mco_ctxbuf* from, _mco_ctxbuf* to) {
  int res = swapcontext(from, to);
  _MCO_UNUSED(res);
  MCO_ASSERT(res == 0);
}

static mco_result _mco_makectx(mco_coro* co, _mco_ctxbuf* ctx, void* stack_base, size_t stack_size) {
  /* Initialize ucontext. */
  if(getcontext(ctx) != 0) {
    MCO_LOG("failed to get ucontext");
    return MCO_MAKE_CONTEXT_ERROR;
  }
  ctx->uc_link = NULL;  /* We never exit from _mco_wrap_main. */
  ctx->uc_stack.ss_sp = stack_base;
  ctx->uc_stack.ss_size = stack_size;
  unsigned int lo = (unsigned int)((size_t)co);
#if defined(_LP64) || defined(__LP64__)
  unsigned int hi = (unsigned int)(((size_t)co)>>32);
  makecontext(ctx, (void (*)(void))_mco_wrap_main, 2, lo, hi);
#else
  makecontext(ctx, (void (*)(void))_mco_wrap_main, 1, lo);
#endif
  return MCO_SUCCESS;
}

#endif /* defined(MCO_USE_UCONTEXT) */

#ifdef MCO_USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

typedef struct _mco_context {
#ifdef MCO_USE_VALGRIND
  unsigned int valgrind_stack_id;
#endif
  _mco_ctxbuf ctx;
  _mco_ctxbuf back_ctx;
} _mco_context;

static void _mco_jumpin(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  _mco_prepare_jumpin(co);
  _mco_switch(&context->back_ctx, &context->ctx); /* Do the context switch. */
}

static void _mco_jumpout(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  _mco_prepare_jumpout(co);
  _mco_switch(&context->ctx, &context->back_ctx); /* Do the context switch. */
}

static mco_result _mco_create_context(mco_coro* co, mco_desc* desc) {
  /* Determine the context and stack address. */
  size_t co_addr = (size_t)co;
  size_t context_addr = _mco_align_forward(co_addr + sizeof(mco_coro), 16);
  size_t storage_addr = _mco_align_forward(context_addr + sizeof(_mco_context), 16);
  size_t stack_addr = _mco_align_forward(storage_addr + desc->storage_size, 16);
  /* Initialize context. */
  _mco_context* context = (_mco_context*)context_addr;
  memset(context, 0, sizeof(_mco_context));
  /* Initialize storage. */
  unsigned char* storage = (unsigned char*)storage_addr;
  memset(storage, 0, desc->storage_size);
  /* Initialize stack. */
  void *stack_base = (void*)stack_addr;
  size_t stack_size = co_addr + desc->coro_size - stack_addr;
#ifdef MCO_ZERO_MEMORY
  memset(stack_base, 0, stack_size);
#endif
  /* Make the context. */
  mco_result res = _mco_makectx(co, &context->ctx, stack_base, stack_size);
  if(res != MCO_SUCCESS) {
    return res;
  }
#ifdef MCO_USE_VALGRIND
  context->valgrind_stack_id = VALGRIND_STACK_REGISTER(stack_addr, stack_addr + stack_size);
#endif
  co->context = context;
  co->stack_base = stack_base;
  co->stack_size = stack_size;
  co->storage = storage;
  co->storage_size = desc->storage_size;
  return MCO_SUCCESS;
}

static void _mco_destroy_context(mco_coro* co) {
#ifdef MCO_USE_VALGRIND
  _mco_context* context = (_mco_context*)co->context;
  if(context && context->valgrind_stack_id != 0) {
    VALGRIND_STACK_DEREGISTER(context->valgrind_stack_id);
    context->valgrind_stack_id = 0;
  }
#else
  _MCO_UNUSED(co);
#endif
}

static MCO_FORCE_INLINE void _mco_init_desc_sizes(mco_desc* desc, size_t stack_size) {
  desc->coro_size = _mco_align_forward(sizeof(mco_coro), 16) +
                    _mco_align_forward(sizeof(_mco_context), 16) +
                    _mco_align_forward(desc->storage_size, 16) +
                    stack_size + 16;
  desc->stack_size = stack_size; /* This is just a hint, it won't be the real one. */
}

#endif /* defined(MCO_USE_UCONTEXT) || defined(MCO_USE_ASM) */

/* ---------------------------------------------------------------------------------------------- */

#ifdef MCO_USE_FIBERS

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>

typedef struct _mco_context {
  void* fib;
  void* back_fib;
} _mco_context;

static void _mco_jumpin(mco_coro* co) {
  void *cur_fib = GetCurrentFiber();
  if(!cur_fib || cur_fib == (void*)0x1e00) { /* See http://blogs.msdn.com/oldnewthing/archive/2004/12/31/344799.aspx */
    cur_fib = ConvertThreadToFiber(NULL);
  }
  MCO_ASSERT(cur_fib != NULL);
  _mco_context* context = (_mco_context*)co->context;
  context->back_fib = cur_fib;
  _mco_prepare_jumpin(co);
  SwitchToFiber(context->fib);
}

static void CALLBACK _mco_wrap_main(void* co) {
  _mco_main((mco_coro*)co);
}

static void _mco_jumpout(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  void* back_fib = context->back_fib;
  MCO_ASSERT(back_fib != NULL);
  context->back_fib = NULL;
  _mco_prepare_jumpout(co);
  SwitchToFiber(back_fib);
}

/* Reverse engineered Fiber struct, used to get stack base. */
typedef struct _mco_fiber {
  LPVOID param;                /* fiber param */
  void* except;                /* saved exception handlers list */
  void* stack_base;            /* top of fiber stack */
  void* stack_limit;           /* fiber stack low-water mark */
  void* stack_allocation;      /* base of the fiber stack allocation */
  CONTEXT context;             /* fiber context */
  DWORD flags;                 /* fiber flags */
  LPFIBER_START_ROUTINE start; /* start routine */
  void **fls_slots;            /* fiber storage slots */
} _mco_fiber;

static mco_result _mco_create_context(mco_coro* co, mco_desc* desc) {
  /* Determine the context address. */
  size_t co_addr = (size_t)co;
  size_t context_addr = _mco_align_forward(co_addr + sizeof(mco_coro), 16);
  size_t storage_addr = _mco_align_forward(context_addr + sizeof(_mco_context), 16);
  /* Initialize context. */
  _mco_context* context = (_mco_context*)context_addr;
  memset(context, 0, sizeof(_mco_context));
  /* Initialize storage. */
  unsigned char* storage = (unsigned char*)storage_addr;
  memset(storage, 0, desc->storage_size);
  /* Create the fiber. */
  _mco_fiber* fib = (_mco_fiber*)CreateFiberEx(desc->stack_size, desc->stack_size, FIBER_FLAG_FLOAT_SWITCH, _mco_wrap_main, co);
  if(!fib) {
    MCO_LOG("failed to create fiber");
    return MCO_MAKE_CONTEXT_ERROR;
  }
  context->fib = fib;
  co->context = context;
  co->stack_base = fib->stack_base;
  co->stack_size = desc->stack_size;
  co->storage = storage;
  co->storage_size = desc->storage_size;
  return MCO_SUCCESS;
}

static void _mco_destroy_context(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  if(context && context->fib) {
    DeleteFiber(context->fib);
    context->fib = NULL;
  }
}

static MCO_FORCE_INLINE void _mco_init_desc_sizes(mco_desc* desc, size_t stack_size) {
  desc->coro_size = _mco_align_forward(sizeof(mco_coro), 16) +
                    _mco_align_forward(sizeof(_mco_context), 16) +
                    _mco_align_forward(desc->storage_size, 16) +
                    16;
  desc->stack_size = stack_size;
}

#elif defined(__EMSCRIPTEN__)

#include <emscripten/fiber.h>

#ifndef MCO_ASYNCFY_STACK_SIZE
#define MCO_ASYNCFY_STACK_SIZE 16384
#endif

typedef struct _mco_context {
  emscripten_fiber_t fib;
  emscripten_fiber_t* back_fib;
} _mco_context;

static emscripten_fiber_t* running_fib = NULL;
static unsigned char main_asyncify_stack[MCO_ASYNCFY_STACK_SIZE];
static emscripten_fiber_t main_fib;

static void _mco_wrap_main(void* co) {
  _mco_main((mco_coro*)co);
}

static void _mco_jumpin(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  emscripten_fiber_t* back_fib = running_fib;
  if(!back_fib) {
    back_fib = &main_fib;
    emscripten_fiber_init_from_current_context(back_fib, main_asyncify_stack, MCO_ASYNCFY_STACK_SIZE);
  }
  running_fib = &context->fib;
  context->back_fib = back_fib;
  _mco_prepare_jumpin(co);
  emscripten_fiber_swap(back_fib, &context->fib); /* Do the context switch. */
}

static void _mco_jumpout(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  running_fib = context->back_fib;
  _mco_prepare_jumpout(co);
  emscripten_fiber_swap(&context->fib, context->back_fib); /* Do the context switch. */
}

static mco_result _mco_create_context(mco_coro* co, mco_desc* desc) {
  if(emscripten_has_asyncify() != 1) {
    MCO_LOG("failed to create fiber because ASYNCIFY is not enabled");
    return MCO_MAKE_CONTEXT_ERROR;
  }
  /* Determine the context address. */
  size_t co_addr = (size_t)co;
  size_t context_addr = _mco_align_forward(co_addr + sizeof(mco_coro), 16);
  size_t storage_addr = _mco_align_forward(context_addr + sizeof(_mco_context), 16);
  size_t stack_addr = _mco_align_forward(storage_addr + desc->storage_size, 16);
  size_t asyncify_stack_addr = _mco_align_forward(stack_addr + desc->stack_size, 16);
  /* Initialize context. */
  _mco_context* context = (_mco_context*)context_addr;
  memset(context, 0, sizeof(_mco_context));
  /* Initialize storage. */
  unsigned char* storage = (unsigned char*)storage_addr;
  memset(storage, 0, desc->storage_size);
  /* Initialize stack. */
  void *stack_base = (void*)stack_addr;
  size_t stack_size = asyncify_stack_addr - stack_addr;
  void *asyncify_stack_base = (void*)asyncify_stack_addr;
  size_t asyncify_stack_size = co_addr + desc->coro_size - asyncify_stack_addr;
#ifdef MCO_ZERO_MEMORY
  memset(stack_base, 0, stack_size);
  memset(asyncify_stack_base, 0, asyncify_stack_size);
#endif
  /* Create the fiber. */
  emscripten_fiber_init(&context->fib, _mco_wrap_main, co, stack_base, stack_size, asyncify_stack_base, asyncify_stack_size);
  co->context = context;
  co->stack_base = stack_base;
  co->stack_size = stack_size;
  co->storage = storage;
  co->storage_size = desc->storage_size;
  return MCO_SUCCESS;
}

static void _mco_destroy_context(mco_coro* co) {
  _mco_context* context = (_mco_context*)co->context;
  /* Nothing to do. */
}

static MCO_FORCE_INLINE void _mco_init_desc_sizes(mco_desc* desc, size_t stack_size) {
  desc->coro_size = _mco_align_forward(sizeof(mco_coro), 16) +
                    _mco_align_forward(sizeof(_mco_context), 16) +
                    _mco_align_forward(desc->storage_size, 16) +
                    _mco_align_forward(stack_size, 16) +
                    _mco_align_forward(MCO_ASYNCFY_STACK_SIZE, 16) +
                    16;
  desc->stack_size = stack_size; /* This is just a hint, it won't be the real one. */
}

#else

#error "Unsupported architecture for fibers method."

#endif

#endif /* MCO_USE_FIBERS */

/* ---------------------------------------------------------------------------------------------- */

mco_desc mco_desc_init(void (*func)(mco_coro* co), size_t stack_size) {
  if(stack_size != 0) {
    /* Stack size should be at least `MCO_MIN_STACK_SIZE`. */
    if(stack_size < MCO_MIN_STACK_SIZE) {
      stack_size = MCO_MIN_STACK_SIZE;
    }
  } else {
    stack_size = MCO_DEFAULT_STACK_SIZE;
  }
  stack_size = _mco_align_forward(stack_size, 16); /* Stack size should be aligned to 16 bytes. */
  mco_desc desc;
  memset(&desc, 0, sizeof(mco_desc));
#ifndef MCO_NO_DEFAULT_ALLOCATORS
  /* Set default allocators. */
  desc.malloc_cb = mco_malloc;
  desc.free_cb = mco_free;
#endif
  desc.func = func;
  desc.storage_size = MCO_DEFAULT_STORAGE_SIZE;
  _mco_init_desc_sizes(&desc, stack_size);
  return desc;
}

static mco_result _mco_validate_desc(mco_desc* desc) {
  if(!desc) {
    MCO_LOG("coroutine description is NULL");
    return MCO_INVALID_ARGUMENTS;
  }
  if(!desc->func) {
    MCO_LOG("coroutine function in invalid");
    return MCO_INVALID_ARGUMENTS;
  }
  if(desc->stack_size < MCO_MIN_STACK_SIZE) {
    MCO_LOG("coroutine stack size is too small");
    return MCO_INVALID_ARGUMENTS;
  }
  if(desc->coro_size < sizeof(mco_coro)) {
    MCO_LOG("coroutine size is invalid");
    return MCO_INVALID_ARGUMENTS;
  }
  return MCO_SUCCESS;
}

mco_result mco_init(mco_coro* co, mco_desc* desc) {
  if(!co) {
    MCO_LOG("attempt to initialize an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  }
  memset(co, 0, sizeof(mco_coro));
  /* Validate coroutine description. */
  mco_result res = _mco_validate_desc(desc);
  if(res != MCO_SUCCESS)
    return res;
  /* Create the coroutine. */
  res = _mco_create_context(co, desc);
  if(res != MCO_SUCCESS)
    return res;
  co->state = MCO_SUSPENDED; /* We initialize in suspended state. */
  co->free_cb = desc->free_cb;
  co->allocator_data = desc->allocator_data;
  co->func = desc->func;
  co->user_data = desc->user_data;
#ifdef _MCO_USE_TSAN
  co->tsan_fiber = __tsan_create_fiber(0);
#endif
  return MCO_SUCCESS;
}

mco_result mco_uninit(mco_coro* co) {
  if(!co) {
    MCO_LOG("attempt to uninitialize an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  }
  /* Cannot uninitialize while running. */
  if(!(co->state == MCO_SUSPENDED || co->state == MCO_DEAD)) {
    MCO_LOG("attempt to uninitialize a coroutine that is not dead or suspended");
    return MCO_INVALID_OPERATION;
  }
  /* The coroutine is now dead and cannot be used anymore. */
  co->state = MCO_DEAD;
#ifdef _MCO_USE_TSAN
  if(co->tsan_fiber != NULL) {
    __tsan_destroy_fiber(co->tsan_fiber);
    co->tsan_fiber = NULL;
  }
#endif
  _mco_destroy_context(co);
  return MCO_SUCCESS;
}

mco_result mco_create(mco_coro** out_co, mco_desc* desc) {
  /* Validate input. */
  if(!out_co) {
    MCO_LOG("coroutine output pointer is NULL");
    return MCO_INVALID_POINTER;
  }
  if(!desc || !desc->malloc_cb || !desc->free_cb) {
    *out_co = NULL;
    MCO_LOG("coroutine allocator description is not set");
    return MCO_INVALID_ARGUMENTS;
  }
  /* Allocate the coroutine. */
  mco_coro* co = (mco_coro*)desc->malloc_cb(desc->coro_size, desc->allocator_data);
  if(!co) {
    MCO_LOG("coroutine allocation failed");
    *out_co = NULL;
    return MCO_OUT_OF_MEMORY;
  }
  /* Initialize the coroutine. */
  mco_result res = mco_init(co, desc);
  if(res != MCO_SUCCESS) {
    desc->free_cb(co, desc->allocator_data);
    *out_co = NULL;
    return res;
  }
  *out_co = co;
  return MCO_SUCCESS;
}

mco_result mco_destroy(mco_coro* co) {
  if(!co) {
    MCO_LOG("attempt to destroy an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  }
  /* Uninitialize the coroutine first. */
  mco_result res = mco_uninit(co);
  if(res != MCO_SUCCESS)
    return res;
  /* Free the coroutine. */
  if(!co->free_cb) {
    MCO_LOG("attempt destroy a coroutine that has no free callback");
    return MCO_INVALID_POINTER;
  }
  co->free_cb(co, co->allocator_data);
  return MCO_SUCCESS;
}

mco_result mco_resume(mco_coro* co) {
  if(!co) {
    MCO_LOG("attempt to resume an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  }
  if(co->state != MCO_SUSPENDED) { /* Can only resume coroutines that are suspended. */
    MCO_LOG("attempt to resume a coroutine that is not suspended");
    return MCO_NOT_SUSPENDED;
  }
  co->state = MCO_RUNNING; /* The coroutine is now running. */
  _mco_jumpin(co);
  return MCO_SUCCESS;
}

mco_result mco_yield(mco_coro* co) {
  if(!co) {
    MCO_LOG("attempt to yield an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  }
  if(co->state != MCO_RUNNING) {  /* Can only yield coroutines that are running. */
    MCO_LOG("attempt to yield a coroutine that is not running");
    return MCO_NOT_RUNNING;
  }
  co->state = MCO_SUSPENDED; /* The coroutine is now suspended. */
  _mco_jumpout(co);
  return MCO_SUCCESS;
}

mco_state mco_status(mco_coro* co) {
  if(co != NULL) {
    return co->state;
  }
  return MCO_DEAD;
}

void* mco_get_user_data(mco_coro* co) {
  if(co != NULL) {
    return co->user_data;
  }
  return NULL;
}

mco_result mco_set_storage(mco_coro* co, const void* src, size_t len) {
  if(!co) {
    MCO_LOG("attempt to use an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  } else if(len > 0) {
    if(len > co->storage_size) {
      MCO_LOG("attempt to set storage from a buffer that is too large");
      return MCO_NOT_ENOUGH_SPACE;
    }
    if(!src) {
      MCO_LOG("attempt to set storage from an invalid pointer");
      return MCO_INVALID_POINTER;
    }
    memcpy(&co->storage[0], src, len);
  }
#ifdef MCO_ZERO_MEMORY
  if(co->storage_available_size > len) {
    /* Clear garbage in old storage. */
    memset(&co->storage[len], 0, co->storage_available_size - len);
  }
#endif
  co->storage_available_size = len;
  return MCO_SUCCESS;
}

mco_result mco_get_storage(mco_coro* co, void* dest, size_t len) {
  if(!co) {
    MCO_LOG("attempt to use an invalid coroutine");
    return MCO_INVALID_COROUTINE;
  } else if(len > 0) {
    if(len > co->storage_size) {
      MCO_LOG("attempt to get storage into a buffer that is too large");
      return MCO_NOT_ENOUGH_SPACE;
    }
    if(!dest) {
      MCO_LOG("attempt to get storage into an invalid pointer");
      return MCO_INVALID_POINTER;
    }
    if(len != co->storage_available_size) {
      MCO_LOG("attempt to get storage of size that mismatches last set size");
      return MCO_NOT_ENOUGH_SPACE;
    }
    memcpy(dest, &co->storage[0], len);
  }
  return MCO_SUCCESS;
}

size_t mco_get_storage_available_size(mco_coro* co) {
  if(co == NULL) {
    return 0;
  }
  return co->storage_available_size;
}

size_t mco_get_storage_size(mco_coro* co) {
  if(co == NULL) {
    return 0;
  }
  return co->storage_size;
}

void* mco_get_storage_pointer(mco_coro* co) {
  if(!co) {
    return NULL;
  }
  return co->storage;
}

mco_result mco_reset_storage(mco_coro* co) {
  return mco_set_storage(co, NULL, 0);
}

#ifdef MCO_NO_MULTITHREAD
mco_coro* mco_running(void) {
  return mco_current_co;
}
#else
static mco_coro* _mco_running(void) {
  return mco_current_co;
}
mco_coro* mco_running(void) {
  /*
  Compilers aggressively optimize the use of TLS by caching loads.
  Since fiber code can migrate between threads it’s possible for the load to be stale.
  To prevent this from happening we avoid inline functions.
  */
  mco_coro* (*volatile func)(void) = _mco_running;
  return func();
}
#endif

const char* mco_result_description(mco_result res) {
  switch(res) {
    case MCO_SUCCESS:
      return "No error";
    case MCO_GENERIC_ERROR:
      return "Generic error";
    case MCO_INVALID_POINTER:
      return "Invalid pointer";
    case MCO_INVALID_COROUTINE:
      return "Invalid coroutine";
    case MCO_NOT_SUSPENDED:
      return "Coroutine not suspended";
    case MCO_NOT_RUNNING:
      return "Coroutine not running";
    case MCO_MAKE_CONTEXT_ERROR:
      return "Make context error";
    case MCO_SWITCH_CONTEXT_ERROR:
      return "Switch context error";
    case MCO_NOT_ENOUGH_SPACE:
      return "Not enough space";
    case MCO_OUT_OF_MEMORY:
      return "Out of memory";
    case MCO_INVALID_ARGUMENTS:
      return "Invalid arguments";
    case MCO_INVALID_OPERATION:
      return "Invalid operation";
    default:
      return "Unknown error";
  }
}

#ifdef __cplusplus
}
#endif

#endif /* MINICORO_IMPL */

/*
This software is available as a choice of the following licenses. Choose
whichever you prefer.

===============================================================================
ALTERNATIVE 1 - Public Domain (www.unlicense.org)
===============================================================================
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

===============================================================================
ALTERNATIVE 2 - MIT No Attribution
===============================================================================
Copyright (c) 2021 Eduardo Bart (https://github.com/edubart/minicoro)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
