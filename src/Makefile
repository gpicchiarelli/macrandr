NAME=macrandr
${NAME}_VERSION = 0.1.0
LOCAL_DAEMON_FILE = /etc/rc.conf.local

CFLAGS+= -fstack-protector-all

all: macrandr
	@chmod 0555 ${NAME}
${NAME}: macrandr.o
	${CC} ${LDFLAGS} -o $@ ${NAME}.o

${NAME}.o: ${NAME}.c ${NAME}.h
	${CC} -c ${CFLAGS} \
		${NAME}.c
.PHONY: install clean
install:
	tar -czNs "|\(.*\)|${NAME}-${MACRANDR_VERSION}/\1|" -f ${NAME}-${MACRANDR_VERSION}.tar.gz *
	cp ${NAME}d /etc/rc.d/${NAME}d
	cp ${NAME} /usr/sbin/${NAME}
	chmod 0555 /etc/rc.d/${NAME}d
	chmod 0555 /usr/sbin/${NAME}

uninstall:
	rm /etc/rc.d/${NAME}d
	rm /usr/sbin/${NAME}


clean:
	rm -f ${NAME} *.o ${NAME}-*.tar.gz tags.*
