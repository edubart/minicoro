CC=gcc
OUTEXT=
CFLAGS=-Og -Wall -Wextra -g -std=c99 -I..
# CFLAGS+=-m32
# CFLAGS+=-DMCO_USE_UCONTEXT
CFLAGS+=-DMCO_USE_VALGRIND
RUNNER=valgrind

# CC=x86_64-w64-mingw32-gcc
# OUTEXT=.exe
# RUNNER=

all: test_minicoro example simple

test: test_minicoro example simple
	$(RUNNER) ./test_minicoro$(OUTEXT)
	$(RUNNER) ./example$(OUTEXT)
	$(RUNNER) ./simple$(OUTEXT)

test_minicoro: test_minicoro.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) test_minicoro.c -o test_minicoro

example: example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) example.c -o example

simple: simple.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) simple.c -o simple

clean:
	rm -f test_minicoro$(OUTEXT) example$(OUTEXT) simple$(OUTEXT)
