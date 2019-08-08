COMMENT= A daemon to change periodically MAC addresses
NAME= macrandr
CATEGORIES= sysutils

MAINTAINER=	Giacomo Picchiarelli <gpicchiarelli@gmail.com>

NO_TEST =	Yes

WRKCONF=
WRKDIR=
WRKSRC=
WRKBUILD=

V= 0.1.0
LOCAL_DAEMON_FILE= /etc/rc.conf.local
HOMEPAGE= https://github.com/gpicchiarelli/${NAME}

PKGNAME= ${NAME}d-${V}
PKGPATH= /usr/ports/mystuff/${NAME}d/src

CFLAGS+= -fstack-protector-all

all: ${NAME}
	@chmod 0555 ${NAME}
${NAME}: ${NAME}.o
	${CC} ${LDFLAGS} -o $@ ${NAME}.o

${NAME}.o: ${NAME}.c ${NAME}.h
	${CC} -c ${CFLAGS} \
		${NAME}.c

.PHONY: install clean uninstall
install:
	tar -czNs "|\(.*\)|${NAME}-${V}/\1|" -f ${NAME}-${V}.tar.gz *
	cp ${NAME}d /etc/rc.d/${NAME}d
	cp ${NAME} /usr/sbin/${NAME}
	chmod 0555 /etc/rc.d/${NAME}d
	chmod 0555 /usr/sbin/${NAME}
	echo "${NAME}d_flags=YES\n" >> ${LOCAL_DAEMON_FILE}

uninstall:
	rm /etc/rc.d/${NAME}d
	rm /usr/sbin/${NAME}
	sed -i '/^${NAME}/d' ${LOCAL_DAEMON_FILE}

clean:
	rm -f ${NAME} *.o ${NAME}-${V}-*.tar.gz tags.*

#.include <bsd.port.mk>
