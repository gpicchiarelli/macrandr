NAME= macrandr
DAEMON_NAME=${NAME}d

MAINTAINER=	Giacomo Picchiarelli <gpicchiarelli@gmail.com>
COMMENT= A daemon to change periodically MAC addresses
V= 0.1.0
PKGNAME= ${DAEMON_NAME}-${V}
DISTNAME= ${DAEMON_NAME}.${V}
LOCAL_DAEMON_FILE= /etc/rc.conf.local
HOMEPAGE= https://github.com/gpicchiarelli/${NAME}
MASTER_SITE= https://github.com/gpicchiarelli/${NAME}

CFLAGS+= -fstack-protector-all
CFLAGS+= -Wunused-variable
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes

dist: clean
	@echo "Cleaning up..."
	@rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.* src/${NAME}.o
	@echo "Cleaning up: done."
	@tar -czNs "|\(.*\)|${DAEMON_NAME}-${V}/\1|" -f ${DAEMON_NAME}-${V}.tar.gz *
	@echo "${DAEMON_NAME}-${V}.tar.gz"
