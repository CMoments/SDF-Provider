CC=gcc
CFLAGS= -g
OBJS=main.o sdf_bind.o sdf_defs.o Cli-function.o
all: main

main: $(OBJS)
	$(CC) $(CFLAGS) -o main $^ -L. -lswsds -ldl -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $<


clean:
	rm -f *.o main
