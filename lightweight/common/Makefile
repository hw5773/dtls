CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

TEST=test
TEST_SRC=test.c bitstring.c prince.c
TEST_OBJ=test.o bitstring.o prince.o

BINS=${TEST}
OBJS=${TEST_OBJ}

CFLAGS=-I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -levent

all: test

test: ${TEST_OBJ}
	${CC} -o ${TEST} ${TEST_OBJ} ${LDFLAGS}

.c.o:
	${CC} ${FLAGS} ${CFLAGS} -c $< -o $@

clean:
	rm ${BINS} ${OBJS}
