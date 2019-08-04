MACRANDR_VERSION = 0.1.0

CFLAGS+= -fstack-protector-all

all: macrandr
	@chmod 711 macrandr
macrandr: macrandr.o
	${CC} ${LDFLAGS} -o $@ macrandr.o

macrandr.o: macrandr.c macrandr.h
	${CC} -c ${CFLAGS} \
		macrandr.c
.PHONY: dist clean
dist:
	tar -czNs "|\(.*\)|macrandr-${MACRANDR_VERSION}/\1|" -f macrandr-${MACRANDR_VERSION}.tar.gz *

clean:
	rm -f macrandr *.o macrandr-*.tar.gz tags.*

