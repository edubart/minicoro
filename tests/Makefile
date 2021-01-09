CC=gcc
CFLAGS=-O2 -Wall -Wextra -std=c99 -I..

all: test_minicoro example

test: test_minicoro example
	./test_minicoro
	./example

test_minicoro: test_minicoro.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) test_minicoro.c -o test_minicoro

example: example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) example.c -o example

clean:
	rm -f test_minicoro example
