CC=gcc
OUTEXT=
CFLAGS=-Og -std=c89
EXTRA_CFLAGS=-Wall -Wextra -I..
RELEASE_CFLAGS=-O3 -flto -march=native -DNDEBUG -DMCO_NO_MULTITHREAD
# CFLAGS+=-m32
# CFLAGS+=-DMCO_USE_FIBERS
# CFLAGS+=-DMCO_USE_ASM
# CFLAGS+=-DMCO_USE_UCONTEXT
# CFLAGS+=-fsanitize=address
# CFLAGS+=-fsanitize=thread
# CFLAGS+=-fsanitize=undefined
# CFLAGS+=-fsanitize=memory -fPIE -pie
# CFLAGS+=-DMCO_USE_VALGRIND
# RUNNER=valgrind

# CC=x86_64-w64-mingw32-gcc
# OUTEXT=.exe
# RUNNER=

all: testsuite example mt-example simple benchmark

test: testsuite example mt-example simple
	$(RUNNER) ./testsuite$(OUTEXT)
	#$(RUNNER) ./example$(OUTEXT)
	#$(RUNNER) ./mt-example$(OUTEXT)
	#$(RUNNER) ./simple$(OUTEXT)

bench: benchmark
	./benchmark$(OUTEXT)

testsuite: testsuite.c ../minicoro.h Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) testsuite.c -o testsuite

example: example.c ../minicoro.h Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) example.c -o example

mt-example: mt-example.c ../minicoro.h Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -std=gnu11 -lpthread mt-example.c -o mt-example

simple: simple.c ../minicoro.h Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -std=c99 simple.c -o simple

benchmark: benchmark.c ../minicoro.h Makefile
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) $(RELEASE_CFLAGS) -std=c99 benchmark.c -o benchmark

clean:
	rm -f testsuite$(OUTEXT) example$(OUTEXT) mt-example$(OUTEXT) simple$(OUTEXT) benchmark$(OUTEXT)

test-linux-full:
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-Og -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O3 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O2 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O1 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O0 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-Og -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O3 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O2 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O1 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O0 -fsanitize=address"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-Og -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O3 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O2 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O1 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O0 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-Og -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O3 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O2 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O1 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O0 -fsanitize=thread"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-Og -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O3 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O2 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O1 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O0 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-Og -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O3 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O2 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O1 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O0 -fsanitize=undefined"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-Og -fsanitize=memory -fPIE -pie"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O3 -fsanitize=memory -fPIE -pie"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O2 -fsanitize=memory -fPIE -pie"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O1 -fsanitize=memory -fPIE -pie"
	$(MAKE) --no-print-directory clean test CC=clang CFLAGS="-O0 -fsanitize=memory -fPIE -pie"
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-Og -DMCO_USE_VALGRIND" RUNNER=valgrind
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O3 -DMCO_USE_VALGRIND" RUNNER=valgrind
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O2 -DMCO_USE_VALGRIND" RUNNER=valgrind
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O1 -DMCO_USE_VALGRIND" RUNNER=valgrind
	$(MAKE) --no-print-directory clean test CC=gcc CFLAGS="-O0 -DMCO_USE_VALGRIND" RUNNER=valgrind
