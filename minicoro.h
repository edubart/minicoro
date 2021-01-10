/*
minicoro.h -- Minimal asymmetric stackful coroutine in pure C99

Project URL: https://github.com/edubart/minicoro

Do this:
  #define MINICORO_IMPL
before you include this file in *one* C file to create the implementation.

LICENSE
  MIT license, see end of file.
*/

#ifndef MINICORO_H
#define MINICORO_H

#ifndef MCO_API
#define MCO_API extern
#endif

#ifndef MCO_IO_DATA_SIZE
#define MCO_IO_DATA_SIZE 1024
#endif

#include <stddef.h> /* for size_t */
#include <stdint.h> /* for uintptr_t, uint32_t, etc.. */

/* ---------------------------------------------------------------------------------------------- */

/* Coroutine states. */
typedef enum mco_state {
  MCO_DEAD,      /* The coroutine has finished normally or was uninitialized before finishing. */
  MCO_NORMAL,    /* The coroutine is active but not running (that is, it has resumed another coroutine). */
  MCO_RUNNING,   /* The coroutine is active and running. */
  MCO_SUSPENDED, /* The coroutine is suspended (in a call to yield, or it has not started running yet). */
} mco_state;

/* Coroutine result codes. */
typedef enum mco_result {
  MCO_SUCCESS,
  MCO_INVALID_POINTER,
  MCO_NOT_SUSPENDED,
  MCO_NOT_RUNNING,
  MCO_MAKE_CONTEXT_ERROR,
  MCO_SWITCH_CONTEXT_ERROR,
  MCO_NO_IO_DATA,
  MCO_NOT_ENOUGH_SPACE,
  MCO_OUT_OF_MEMORY,
  MCO_INVALID_ARGUMENTS,
  MCO_INVALID_OPERATION,
} mco_result;

typedef struct mco_coro mco_coro;
typedef void (*mco_func)(mco_coro* co);

/* Coroutine structure. */
struct mco_coro {
  void* context;
  mco_state state;
  mco_func func;
  mco_coro* prev_co;
  void* user_data;
  void* allocator_data;
  void (*free_cb)(void* ptr, void* allocator_data);
  size_t io_data_size;
  uint8_t io_data[MCO_IO_DATA_SIZE];
};

/* Structure used to initialize a coroutine. */
typedef struct mco_desc {
  mco_func func;        /* entry point function for the coroutine */
  uintptr_t coro_size;  /* coroutine size, must be initialized through mco_init_desc */
  uintptr_t stack_size; /* coroutine stack size, must be initialized through mco_init_desc */
  void* user_data;      /* coroutine user data, can be retrieved with mco_get_user_data */
  /* custom allocation interface */
  void* (*malloc_cb)(size_t size, void* allocator_data); /* custom allocation function */
  void  (*free_cb)(void* ptr, void* allocator_data);     /* custom deallocation function */
  void* allocator_data; /* user data passed to malloc/free allocation functions */
} mco_desc;

/* Initialize description of a coroutine, use this if you want to manually allocate. */
MCO_API mco_desc mco_desc_init(mco_func func, uintptr_t stack_size);

/* Initialize the coroutine. */
MCO_API mco_result mco_init(mco_coro* co, mco_desc* desc);

/* Uninitialize the coroutine. */
/* The operation may fail if the coroutine is not dead or suspended, in this case, the operation is ignored. */
MCO_API mco_result mco_uninit(mco_coro* co);

/* Create a new coroutine. It allocates and call mco_init. */
MCO_API mco_result mco_create(mco_coro** out_co, mco_desc* desc);

/* Uninitialize the coroutine and free all resources. */
/* The operation may fail if the coroutine is not dead or suspended, in this case, the operation is ignored. */
MCO_API mco_result mco_destroy(mco_coro* co);

/* Returns the status of the coroutine. */
MCO_API mco_state mco_status(mco_coro* co);

/* Returns the running coroutine in the current thread. */
MCO_API mco_coro* mco_running();

/* Starts or continues the execution of the coroutine. */
MCO_API mco_result mco_resume(mco_coro* co);

/* Suspends the execution of the coroutine. */
MCO_API mco_result mco_yield(mco_coro *co);

/* Set the coroutine IO data. Use to pass results between yield and resume. */
MCO_API mco_result mco_set_io_data(mco_coro* co, const void* src, size_t len);

/* Get the coroutine IO data. Use to retrieve results between yield and resume. */
MCO_API mco_result mco_get_io_data(mco_coro* co, void* dest, size_t maxlen);

/* Get the coroutine IO data size. */
MCO_API size_t mco_get_io_data_size();

/* Clear the coroutine IO data. Call this to reset IO data before a yield or resume. */
MCO_API void mco_reset_io_data(mco_coro* co);

/* Shortcut for mco_get_io_data + mco_reset_io_data. Reset is called even on errors. */
MCO_API mco_result mco_get_and_reset_io_data(mco_coro* co, void* dest, size_t maxlen);

/* Retrieve coroutine user data supplied on coroutine creation. */
MCO_API void* mco_get_user_data(mco_coro* co);

/* Get a string description of result. */
MCO_API const char* mco_result_description(mco_result res);

#endif /* MINICORO_H */

#ifdef MINICORO_IMPL

/* ---------------------------------------------------------------------------------------------- */

#ifndef MCO_MIN_STACK_SIZE
#define MCO_MIN_STACK_SIZE 32768
#endif

#ifndef MCO_DEFAULT_STACK_SIZE
#define MCO_DEFAULT_STACK_SIZE 57344 /* Don't use multiples of 64K to avoid D-cache aliasing conflicts. */
#endif

#ifdef _WIN32
#define MCO_USE_FIBERS
#else
#define MCO_USE_UCONTEXT
#endif

#define _MCO_UNUSED(x) (void)(x)

#ifndef MCO_DEBUG
  #ifndef NDEBUG
    #define MCO_DEBUG
  #endif
#endif

#ifndef MCO_LOG
  #ifdef MCO_DEBUG
    #include <stdio.h>
    #define MCO_LOG(s) puts(s)
  #else
    #define MCO_LOG(s)
  #endif
#endif

#ifndef MCO_UNREACHABLE
#define MCO_UNREACHABLE() __builtin_unreachable()
#endif

#ifndef MCO_ASSERT
  #include <assert.h>
  #define MCO_ASSERT(c) assert(c)
#endif

#ifdef MCO_NO_MULTITHREAD
  #define _MCO_THREAD_LOCAL
#else
  #ifdef thread_local
    #define _MCO_THREAD_LOCAL thread_local
  #elif __STDC_VERSION__ >= 201112 && !defined(__STDC_NO_THREADS__)
    #define _MCO_THREAD_LOCAL _Thread_local
  #elif defined(_WIN32) && (defined(_MSC_VER) || defined(__ICL) ||  defined(__DMC__) ||  defined(__BORLANDC__))
    #define _MCO_THREAD_LOCAL __declspec(thread)
  #elif defined(__GNUC__) || defined(__SUNPRO_C) || defined(__xlC__)
    #define _MCO_THREAD_LOCAL __thread
  #else /* mco_running() will be thread unsafe */
    #define _MCO_THREAD_LOCAL
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

#include <string.h> /* for memcpy, memset */

/* Utility for aligning addresses. */
static uintptr_t _mco_align_forward(uintptr_t addr, uintptr_t align) {
  return (addr + (align-1)) & ~(align-1);
}

/* Variable holding the current running coroutine per thread. */
static _MCO_THREAD_LOCAL mco_coro* mco_current_co = NULL;

static void _mco_prepare_jumpin(mco_coro* co) {
  /* Set the old coroutine to normal state and update it. */
  mco_coro* prev_co = mco_current_co;
  co->prev_co = prev_co;
  if(prev_co) {
    MCO_ASSERT(prev_co->state == MCO_RUNNING);
    prev_co->state = MCO_NORMAL;
  }
  mco_current_co = co;
}

static void _mco_prepare_jumpout(mco_coro* co) {
  /* Switch back to the previous running coroutine. */
  MCO_ASSERT(mco_current_co == co);
  mco_coro* prev_co = co->prev_co;
  co->prev_co = NULL;
  if(prev_co) {
    MCO_ASSERT(prev_co->state == MCO_NORMAL);
    prev_co->state = MCO_RUNNING;
  }
  mco_current_co = prev_co;
}

static mco_result _mco_jumpin(mco_coro* co);
static mco_result _mco_jumpout(mco_coro* co);

static void _mco_main_inner(mco_coro* co) {
  co->func(co); /* Run the coroutine function. */
  co->state = MCO_DEAD; /* Coroutine finished successfully, set state to dead. */
  _mco_jumpout(co); /* Jump back to the old context */
}

/* ---------------------------------------------------------------------------------------------- */

#ifdef MCO_USE_UCONTEXT

#include <ucontext.h>

typedef struct _mco_ucontext {
  ucontext_t ctx;
  ucontext_t back_ctx;
} _mco_ucontext;

static mco_result _mco_switch(ucontext_t* from, ucontext_t* to) {
  if(swapcontext(from, to) == -1) {
    /* This error is fatal, expect the library to be in a bad state when this happens. */
    MCO_LOG("swap context fatal error");
    return MCO_SWITCH_CONTEXT_ERROR;
  }
  return MCO_SUCCESS;
}

static mco_result _mco_jumpin(mco_coro* co) {
  _mco_prepare_jumpin(co);
  _mco_ucontext* context = (_mco_ucontext*)co->context;
  return _mco_switch(&context->back_ctx, &context->ctx); /* Do the context switch. */
}

static mco_result _mco_jumpout(mco_coro* co) {
  _mco_prepare_jumpout(co);
  _mco_ucontext* context = (_mco_ucontext*)co->context;
  return _mco_switch(&context->ctx, &context->back_ctx); /* Do the context switch. */
}

#if defined(_LP64) || defined(__LP64__)
static void _mco_main(uint32_t lo, uint32_t hi) {
  mco_coro* co = (mco_coro*)(((uintptr_t)lo) | (((uintptr_t)hi) << 32)); /* Extract coroutine pointer. */
  _mco_main_inner(co);
}
#else
static void _mco_main(uint32_t lo) {
  mco_coro* co = (mco_coro*)((uintptr_t)lo); /* Extract coroutine pointer. */
  _mco_main_inner(co);
}
#endif

static mco_result _mco_create_context(mco_coro* co, mco_desc* desc) {
  /* Determine the context and stack address. */
  uintptr_t co_addr = (uintptr_t)co;
  uintptr_t context_addr = _mco_align_forward(co_addr + sizeof(mco_coro), 16);
  uintptr_t stack_addr = _mco_align_forward(context_addr + sizeof(_mco_ucontext), 16);
  /* Initialize context. */
  _mco_ucontext* context = (_mco_ucontext*)context_addr;
  memset(context, 0, sizeof(_mco_ucontext));
  /* Initialize stack. */
  void *stack_ptr = (void*)stack_addr;
  uintptr_t stack_size = co_addr + desc->coro_size - stack_addr;
#ifdef MCO_ZERO_MEMORY
  memset(stack_ptr, 0, stack_size);
#endif
  /* Initialize ucontext. */
  ucontext_t* ctx = &context->ctx;
  if(getcontext(ctx) != 0) {
    MCO_LOG("get context context");
    return MCO_MAKE_CONTEXT_ERROR;
  }
  ctx->uc_link = NULL;  /* We never exit from _mco_main. */
  ctx->uc_stack.ss_sp = stack_ptr;
  ctx->uc_stack.ss_size = stack_size;
  uint32_t lo = (uint32_t)((uintptr_t)co);
#if defined(_LP64) || defined(__LP64__)
  uint32_t hi = (uint32_t)(((uintptr_t)co)>>32);
  makecontext(ctx, (void (*)(void))_mco_main, 2, lo, hi);
#else
  makecontext(ctx, (void (*)(void))_mco_main, 1, lo);
#endif
  co->context = context;
  return MCO_SUCCESS;
}

static mco_result _mco_destroy_context(mco_coro* co) {
  _MCO_UNUSED(co);
  /* Nothing to do. */
  return MCO_SUCCESS;
}

static void _mco_init_desc_sizes(mco_desc* desc, uintptr_t stack_size) {
   /* Add enough space to hold mco_coro and _mco_ucontext. */
  int extra_size = _mco_align_forward(_mco_align_forward(sizeof(mco_coro), 16) + sizeof(_mco_ucontext), 16);
  desc->coro_size = _mco_align_forward(stack_size + extra_size, 4096);
  desc->stack_size = stack_size; /* This is just a hint, it won't be the real one. */
}

#endif /* MCO_USE_UCONTEXT*/

/* ---------------------------------------------------------------------------------------------- */

#ifdef MCO_USE_FIBERS

#include <sdkddkver.h> /* for _WIN32_WINNT */
#include <windows.h>

typedef struct _mco_fcontext {
  void* fib;
  void* back_fib;
  uintptr_t stack_size;
} _mco_fcontext;

static mco_result _mco_jumpin(mco_coro* co) {
  void *cur_fib = GetCurrentFiber();
  /* See: http://blogs.msdn.com/oldnewthing/archive/2004/12/31/344799.aspx */
  if(cur_fib == NULL || cur_fib == (void*)0x1e00) {
    cur_fib = ConvertThreadToFiber(NULL);
  }
  if(cur_fib == NULL) {
    MCO_LOG("failed to get back fiber");
    return MCO_SWITCH_CONTEXT_ERROR;
  }
  _mco_fcontext* context = (_mco_fcontext*)co->context;
  context->back_fib = cur_fib;
  _mco_prepare_jumpin(co);
  SwitchToFiber(context->fib);
  return MCO_SUCCESS;
}

static CALLBACK void _mco_main(mco_coro* co) {
  _mco_main_inner(co);
}

static mco_result _mco_jumpout(mco_coro* co) {
  _mco_prepare_jumpout(co);
  _mco_fcontext* context = (_mco_fcontext*)co->context;
  void* back_fib = context->back_fib;
  MCO_ASSERT(back_fib != NULL);
  context->back_fib = NULL;
  SwitchToFiber(back_fib);
  return MCO_SUCCESS;
}

static mco_result _mco_create_context(mco_coro* co, mco_desc* desc) {
  /* Determine the context address. */
  uintptr_t co_addr = (uintptr_t)co;
  uintptr_t context_addr = _mco_align_forward(co_addr + sizeof(mco_coro), 16);
  _mco_fcontext* context = (_mco_fcontext*)context_addr;
  /* Create the fiber */
  void* fib = CreateFiber(desc->stack_size, (LPFIBER_START_ROUTINE)_mco_main, co);
  if(!fib) {
    MCO_LOG("failed to create fiber");
    return MCO_MAKE_CONTEXT_ERROR;
  }
  context->fib = fib;
  co->context = context;
  return MCO_SUCCESS;
}

static mco_result _mco_destroy_context(mco_coro* co) {
  _mco_fcontext* context = (_mco_fcontext*)co->context;
  if(context->fib) {
    DeleteFiber(context->fib);
    context->fib = NULL;
  }
  return MCO_SUCCESS;
}

static void _mco_init_desc_sizes(mco_desc* desc, uintptr_t stack_size) {
  desc->coro_size = _mco_align_forward(_mco_align_forward(sizeof(mco_coro), 16) + sizeof(_mco_fcontext), 16);
  desc->stack_size = stack_size;
}

#endif /* MCO_USE_FIBERS */

/* ---------------------------------------------------------------------------------------------- */

mco_desc mco_desc_init(mco_func func, uintptr_t stack_size) {
  if(stack_size != 0) {
    /* Stack size should be at least MCO_MIN_STACK_SIZE. */
    if(stack_size < MCO_MIN_STACK_SIZE) {
      stack_size = MCO_MIN_STACK_SIZE;
    }
  } else {
    stack_size = MCO_DEFAULT_STACK_SIZE;
  }
  mco_desc desc;
  memset(&desc, 0, sizeof(mco_desc));
#ifndef MCO_NO_DEFAULT_ALLOCATORS
  /* Set default allocators. */
  desc.malloc_cb = mco_malloc;
  desc.free_cb = mco_free;
#endif
  desc.func = func;
  _mco_init_desc_sizes(&desc, stack_size);
  return desc;
}

static mco_result _mco_validate_desc(mco_desc* desc) {
  if(!desc) {
    MCO_LOG("coroutine description is NULL");
    return MCO_INVALID_ARGUMENTS;
  }
  if(!desc->func) {
    MCO_LOG("invalid function in coroutine description");
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
    MCO_LOG("attempt to initialize a NULL coroutine pointer");
    return MCO_INVALID_POINTER;
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
  return MCO_SUCCESS;
}

mco_result mco_uninit(mco_coro* co) {
  if(!co) {
    MCO_LOG("passed a NULL coroutine pointer");
    return MCO_INVALID_POINTER;
  }
  /* Cannot uninitialize while running. */
  if(!(co->state == MCO_SUSPENDED || co->state == MCO_DEAD)) {
    MCO_LOG("attempt to uninitialize a coroutine that is not dead or suspended");
    return MCO_INVALID_OPERATION;
  }
  /* The coroutine is now dead and cannot be used anymore. */
  co->state = MCO_DEAD;
  return _mco_destroy_context(co);
}

mco_result mco_create(mco_coro** out_co, mco_desc* desc) {
  /* Validate input. */
  if(!out_co) {
    MCO_LOG("passed a NULL output coroutine pointer");
    return MCO_INVALID_POINTER;
  }
  if(!desc || !desc->malloc_cb || !desc->free_cb) {
    *out_co = NULL;
    MCO_LOG("coroutine description allocator callbacks is not set");
    return MCO_INVALID_ARGUMENTS;
  }
  /* Allocate the coroutine */
  mco_coro *co = (mco_coro*)desc->malloc_cb(desc->coro_size, desc->allocator_data);
  if(!co) {
    MCO_LOG("failed to allocate coroutine");
    *out_co = NULL;
    return MCO_OUT_OF_MEMORY;
  }
  /* Initialize the coroutine */
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
    MCO_LOG("attempt to destroy a NULL coroutine");
    return MCO_INVALID_POINTER;
  }
  /* Uninitialize the coroutine first. */
  mco_result res = mco_uninit(co);
  if(res != MCO_SUCCESS)
    return res;
  /* Free */
  if(!co->free_cb) {
    MCO_LOG("failed to deallocate coroutine because free callback is NULL");
    return MCO_INVALID_POINTER;
  }
  co->free_cb(co, co->allocator_data);
  return MCO_SUCCESS;
}

mco_state mco_status(mco_coro* co) {
  MCO_ASSERT(co != NULL);
  return co->state;
}

mco_coro* mco_running() {
  return mco_current_co;
}

mco_result mco_resume(mco_coro* co) {
  MCO_ASSERT(co != NULL);
  if(co->state != MCO_SUSPENDED) { /* Can only resume coroutines that are suspended. */
    MCO_LOG("attempt to resume a coroutine that is not suspended");
    return MCO_NOT_SUSPENDED;
  }
  co->state = MCO_RUNNING; /* The coroutine is now running. */
  return _mco_jumpin(co);
}

mco_result mco_yield(mco_coro *co) {
  MCO_ASSERT(co != NULL);
  if(co->state != MCO_RUNNING) {  /* Can only yield coroutines that are running. */
    MCO_LOG("attempt to yield a coroutine that is not running");
    return MCO_NOT_RUNNING;
  }
  co->state = MCO_SUSPENDED; /* The coroutine is now suspended. */
  return _mco_jumpout(co);
}

mco_result mco_set_io_data(mco_coro* co, const void* src, size_t len) {
  MCO_ASSERT(co != NULL);
  if(len > MCO_IO_DATA_SIZE) {
    MCO_LOG("not enough space for setting io data");
    return MCO_NOT_ENOUGH_SPACE;
  } else if(len > 0) {
    if(!src) {
      MCO_LOG("invalid pointer when setting io data");
      return MCO_INVALID_POINTER;
    }
    memcpy(&co->io_data[0], src, len);
#ifdef MCO_ZERO_MEMORY
    if(len < co->io_data_size) {
      /* Clear garbage in old IO data . */
      memset(&co->io_data[len], 0, co->io_data_size - len);
    }
#endif
  }
  co->io_data_size = len;
  return MCO_SUCCESS;
}

mco_result mco_get_io_data(mco_coro* co, void* dest, size_t maxlen) {
  MCO_ASSERT(co != NULL);
  if(co->io_data_size == 0) {
    return MCO_NO_IO_DATA;
  } else if(co->io_data_size > maxlen) {
    MCO_LOG("not enough space for getting io data");
    return MCO_NOT_ENOUGH_SPACE;
  } else if(co->io_data_size > 0) {
    if(!dest) {
      MCO_LOG("invalid pointer when getting io data");
      return MCO_INVALID_POINTER;
    }
    memcpy(dest, &co->io_data[0], co->io_data_size);
  }
  return MCO_SUCCESS;
}

size_t mco_get_io_data_size(mco_coro* co) {
  MCO_ASSERT(co != NULL);
  return co->io_data_size;
}

void mco_reset_io_data(mco_coro* co) {
  MCO_ASSERT(co != NULL);
  mco_set_io_data(co, NULL, 0);
}

mco_result mco_get_and_reset_io_data(mco_coro* co, void* dest, size_t maxlen) {
  MCO_ASSERT(co != NULL);
  mco_result res = mco_get_io_data(co, dest, maxlen);
  mco_reset_io_data(co);
  return res;
}

void* mco_get_user_data(mco_coro* co) {
  MCO_ASSERT(co != NULL);
  return co->user_data;
}

const char* mco_result_description(mco_result res) {
  switch(res) {
    case MCO_SUCCESS:
      return "No error";
    case MCO_INVALID_POINTER:
      return "Invalid pointer";
    case MCO_NOT_SUSPENDED:
      return "Coroutine not suspended";
    case MCO_NOT_RUNNING:
      return "Coroutine not running";
    case MCO_MAKE_CONTEXT_ERROR:
      return "Make context error";
    case MCO_SWITCH_CONTEXT_ERROR:
      return "Switch context error";
    case MCO_NO_IO_DATA:
      return "No IO data";
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

#endif /* MINICORO_IMPL */

/*
The MIT License (MIT)

Copyright (c) 2021 Eduardo Bart (https://github.com/edubart/minicoro)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
