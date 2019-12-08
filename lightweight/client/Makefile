CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

CLIENT=client
CLIENT_SRC=client.c ../common/prince.c ../common/bitstring.c
CLIENT_OBJ=client.o ../common/prince.o ../common/bitstring.o

BINS=${CLIENT}
OBJS=${CLIENT_OBJ}

CFLAGS=-I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -lpthread

all: client

client: ${CLIENT_OBJ}
	${CC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

client.o: ${CLIENT_SRC}
	${CC} ${FLAGS} ${CFLAGS} -c $<

clean:
	rm ${BINS} ${OBJS}
