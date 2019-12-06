CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

CLIENT=gateway
CLIENT_SRC=gateway.c
CLIENT_OBJ=gateway.o

BINS=${CLIENT}
OBJS=${CLIENT_OBJ}

CFLAGS=-I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -lpthread -levent

all: gateway

gateway: ${CLIENT_OBJ}
	${CC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

gateway.o: ${CLIENT_SRC}
	${CC} ${FLAGS} ${CFLAGS} -c $<

clean:
	rm ${BINS} ${OBJS}
