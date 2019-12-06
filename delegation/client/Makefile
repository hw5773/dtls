CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

CLIENT=client
CLIENT_SRC=client.c 
CLIENT_OBJ=client.o 

BINS=${CLIENT}
OBJS=${CLIENT_OBJ}

CFLAGS=-DTIME_LOG -I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -lpthread

all: client

client: ${CLIENT_OBJ}
	${CC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

.c.o:
	${CC} ${FLAGS} ${CFLAGS} -c $< -o $@

clean:
	rm ${BINS} ${OBJS}
