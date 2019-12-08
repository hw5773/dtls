CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

SERVER=server
SERVER_SRC=server.c func.c
SERVER_OBJ=server.o func.o

BINS=${SERVER}
OBJS=${SERVER_OBJ}

CFLAGS=-DTIME_LOG -I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -levent

all: server

server: ${SERVER_OBJ}
	${CC} -o ${SERVER} ${SERVER_OBJ} ${LDFLAGS}

.c.o:
	${CC} ${FLAGS} ${CFLAGS} -c $< -o $@

clean:
	rm ${BINS} ${OBJS}
