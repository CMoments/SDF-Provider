CC = gcc
CFLAGS = -g -O0 -fPIC
LDFLAGS = -shared -Wl,--export-dynamic -Wl,-u,OSSL_provider_init -lcrypto

all: libtongsuo_provider.so test_tongsuo_provider

libtongsuo_provider.so: simple_sm4.o simple_rand.o tongsuo_provider.o
	$(CC) $(LDFLAGS) -g -o $@ $^

simple_rand.o: simple_rand.c
	$(CC) $(CFLAGS) -c -o $@ $<

simple_sm4.o: simple_sm4.c
	$(CC) $(CFLAGS) -c -o $@ $<

tongsuo_provider.o: tongsuo_provider.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_tongsuo_provider: test_tongsuo_provider.c libtongsuo_provider.so
	$(CC) -g -o $@ $< -lcrypto -L. -ltongsuo_provider

test:
	LD_LIBRARY_PATH=. ./test_tongsuo_provider

clean:
	rm -f libtongsuo_provider.so simple_sm4.o simple_rand.o test_tongsuo_provider

.PHONY: all test clean