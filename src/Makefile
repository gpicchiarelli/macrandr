MACRANDR_VERSION = 0.1.0

CFLAGS+= -fstack-protector-all

all: macrandr
	@chmod 711 macrandr
macrandr: macrandr.o
	${CC} ${LDFLAGS} -o $@ macrandr.o

macrandr.o: macrandr.c macrandr.h
	${CC} -c ${CFLAGS} \
		macrandr.c
.PHONY: install clean
install:
	tar -czNs "|\(.*\)|macrandr-${MACRANDR_VERSION}/\1|" -f macrandr-${MACRANDR_VERSION}.tar.gz *
	cp macrandrd /etc/rc.d/macrandrd
	cp macrandr /usr/sbin/macrandr
	chmod 711 /etc/rc.d/macrandrd

clean:
	rm -f macrandr *.o macrandr-*.tar.gz tags.*
