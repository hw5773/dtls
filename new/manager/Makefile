CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

MANAGER=manager
MANAGER_SRC=manager.c func.c
MANAGER_OBJ=manager.o func.o

BINS=${MANAGER}
OBJS=${MANAGER_OBJ}

CFLAGS=-DTIME_LOG -I../../include -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ldl -levent

all: manager

manager: ${MANAGER_OBJ}
	${CC} -o ${MANAGER} ${MANAGER_OBJ} ${LDFLAGS}

.c.o:
	${CC} ${FLAGS} ${CFLAGS} -c $< -o $@

clean:
	rm ${BINS} ${OBJS}
