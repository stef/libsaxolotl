CC=gcc
CFLAGS+= -g -Wall -I/usr/include/sodium -I.
LDFLAGS+= -lsodium

utils=utils/genidkey utils/setup utils/handshake utils/box utils/unbox

all: test demo $(utils)

test: axolotl-dbg.o test.c
	$(CC) $(CFLAGS) -DAXOLOTL_DEBUG $(LDFLAGS) $^ -o $@

axolotl-dbg.o: axolotl.c axolotl.h
	$(CC) $(CFLAGS) -DAXOLOTL_DEBUG $(LDFLAGS) axolotl.c -c -o $@

axolotl.o: axolotl.c

demo: demo.c axolotl.o

utils/genidkey: axolotl.o utils/genidkey.c

utils/setup: axolotl.o utils/setup.c

utils/handshake: axolotl.o utils/handshake.c

utils/box: axolotl.o utils/box.c

utils/unbox: axolotl.o utils/unbox.c

clean:
	rm -f *.o test demo $(utils)

