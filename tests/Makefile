CC=gcc
OUTEXT=
CFLAGS=-Og -Wall -Wextra -g -std=c99 -I..
RELEASE_CFLAGS=-O3 -flto -march=native -DNDEBUG -DMCO_NO_MULTITHREAD
CFLAGS+=-m32
# CFLAGS+=-DMCO_USE_UCONTEXT
CFLAGS+=-DMCO_USE_VALGRIND
RUNNER=valgrind

# CC=x86_64-w64-mingw32-gcc
# OUTEXT=.exe
# RUNNER=

all: testsuite example simple benchmark

test: testsuite example simple
	$(RUNNER) ./testsuite$(OUTEXT)
	$(RUNNER) ./example$(OUTEXT)
	$(RUNNER) ./simple$(OUTEXT)

bench: benchmark
	./benchmark$(OUTEXT)

testsuite: testsuite.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) testsuite.c -o testsuite

example: example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) example.c -o example

simple: simple.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) simple.c -o simple

benchmark: benchmark.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) $(RELEASE_CFLAGS) benchmark.c -o benchmark

clean:
	rm -f testsuite$(OUTEXT) example$(OUTEXT) simple$(OUTEXT) benchmark$(OUTEXT)
