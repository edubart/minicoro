CC=gcc
OUTEXT=
#CC=x86_64-w64-mingw32-gcc
#OUTEXT=.exe
CFLAGS=-O2 -Wall -Wextra -std=c99 -I..

all: test_minicoro example

test: test_minicoro example
	./test_minicoro$(OUTEXT)
	./example$(OUTEXT)

test_minicoro: test_minicoro.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) test_minicoro.c -o test_minicoro

example: example.c ../minicoro.h Makefile
	$(CC) $(CFLAGS) example.c -o example

clean:
	rm -f test_minicoro example
