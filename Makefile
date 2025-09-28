CC=gcc
CFLAGS= -g
OBJS=main.o sdf_bind.o sdf_defs.o Cli-function.o
TARGET=sdf

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $^ -L. -lswsds -ldl -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean