CC=gcc
CFLAGS+= -g -Wall -I/usr/include/sodium
LDFLAGS+= -lsodium

all: test demo

test: axolotl-dbg.o test.c
	$(CC) $(CFLAGS) -DAXOLOTL_DEBUG $(LDFLAGS) $^ -o $@

axolotl-dbg.o: axolotl.c axolotl.h
	$(CC) $(CFLAGS) -DAXOLOTL_DEBUG $(LDFLAGS) axolotl.c -c -o $@

axolotl.o: axolotl.c

demo: demo.c axolotl.o

clean:
	rm *.o test demo

