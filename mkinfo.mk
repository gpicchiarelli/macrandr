NAME= macrandr
DAEMON_NAME=${NAME}d

V= 0.1.0
PKGNAME= ${DAEMON_NAME}-${V}
DISTNAME= ${DAEMON_NAME}.${V}

LOCAL_DAEMON_FILE= /etc/rc.conf.local

PREFIX=${LOCALBASE}/usr/local
BINDIR=${PREFIX}/sbin/

MANDIR=${LOCALBASE}/usr/share/man/man8/

CFLAGS+= -fstack-protector-all
CFLAGS+= -Wunused-variable
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes

dist:
	@echo "Cleaning up..."
	@rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.* src/${NAME}.o
	@echo "Cleaning up: done."
	@tar -czNs "|\(.*\)|${DAEMON_NAME}-${V}/\1|" -f ../${DAEMON_NAME}-${V}.tar.gz *
	@echo "${DAEMON_NAME}-${V}.tar.gz"


uninstall_and_dist: clean
	@echo "Cleaning up..."
	@rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.* src/${NAME}.o
	@echo "Cleaning up: done."
	@tar -czNs "|\(.*\)|${DAEMON_NAME}-${V}/\1|" -f ../${DAEMON_NAME}-${V}.tar.gz *
	@echo "${DAEMON_NAME}-${V}.tar.gz"
