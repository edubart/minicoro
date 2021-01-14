CC=gcc
OUTEXT=
CFLAGS=-Og -g -Wall -Wextra -std=c89 -I..
RELEASE_CFLAGS=-O3 -flto -march=native -DNDEBUG -DMCO_NO_MULTITHREAD
# CFLAGS+=-m32
# CFLAGS+=-DMCO_USE_ASM
# CFLAGS+=-DMCO_USE_UCONTEXT
# CFLAGS+=-fsanitize=address
# CFLAGS+=-fsanitize=thread
# CFLAGS+=-DMCO_USE_VALGRIND
# RUNNER=valgrind

# CC=x86_64-w64-mingw32-gcc
# OUTEXT=.exe
# RUNNER=

all: testsuite example mt-example simple benchmark

test: testsuite example mt-example simple
	$(RUNNER) ./testsuite$(OUTEXT)
	$(RUNNER) ./example$(OUTEXT)
	$(RUNNER) ./mt-example$(OUTEXT)
	$(RUNNER) ./simple$(OUTEXT)

bench: benchmark
	./benchmark$(OUTEXT)

testsuite: testsuite.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) testsuite.c -o testsuite

example: example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) example.c -o example

mt-example: mt-example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) -std=gnu11 -lpthread mt-example.c -o mt-example

simple: simple.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) -std=c99 simple.c -o simple

benchmark: benchmark.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) $(RELEASE_CFLAGS) -std=c99 benchmark.c -o benchmark

clean:
	rm -f testsuite$(OUTEXT) example$(OUTEXT) mt-example$(OUTEXT) simple$(OUTEXT) benchmark$(OUTEXT)
