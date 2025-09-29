CC=gcc
CFLAGS= -g
OBJS=main.o sdf_bind.o sdf_defs.o testcases.o

UTIL_OBJ=utils.o

all: main

main: $(OBJS)
	$(CC) $(CFLAGS) -o main $^ -L. -lswsds -ldl -lssl -lcrypto
util: $(UTIL_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $<



clean:
	rm -f *.o main util
