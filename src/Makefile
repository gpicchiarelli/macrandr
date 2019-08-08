COMMENT= A daemon to change periodically MAC addresses
NAME= macrandr


DAEMON_NAME=${NAME}d
CATEGORIES= sysutils

PERMIT_PACKAGE= yes
PERMIT_PACKAGE_CDROM= yes
PERMIT_PACKAGE_FTP= yes
PERMIT_DISTFILES_CDROM= yes
PERMIT_DISTFILES_FTP= yes

MAINTAINER=	Giacomo Picchiarelli <gpicchiarelli@gmail.com>

NO_TEST =	Yes

WRKCONF=
WRKDIR=
WRKSRC=
WRKBUILD=

V= 0.1.0
LOCAL_DAEMON_FILE= /etc/rc.conf.local
HOMEPAGE= https://github.com/gpicchiarelli/${NAME}
MASTER_SITE= https://github.com/gpicchiarelli/${NAME}

PKGNAME= ${DAEMON_NAME}-${V}
DISTNAME= ${DAEMON_NAME}.${V}
PKGPATH= /usr/ports/${CATEGORIES}/${DAEMON_NAME}/src

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
	#tar -czNs "|\(.*\)|${NAME}-${V}/\1|" -f ${DAEMON_NAME}-${V}.tar.gz *
	cp ${DAEMON_NAME} /etc/rc.d/${DAEMON_NAME}
	cp ${NAME} /usr/sbin/${NAME}
	chmod 0555 /etc/rc.d/${DAEMON_NAME}
	chmod 0555 /usr/sbin/${NAME}
	echo "${NAME}d_flags=YES\n" >> ${LOCAL_DAEMON_FILE}
	cp man/${DAEMON_NAME}.8 /usr/share/man/man8/${DAEMON_NAME}.8
	rcctl enable ${DAEMON_NAME}
	rcctl start ${DAEMON_NAME}

uninstall:
	rcctl stop ${DAEMON_NAME}
	rcctl disable ${DAEMON_NAME}
	rm /etc/rc.d/${DAEMON_NAME}
	rm /usr/sbin/${NAME}
	sed -i '/^${NAME}/d' ${LOCAL_DAEMON_FILE}
	rm /usr/share/man/man8/${DAEMON_NAME}.8

clean:
	rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.*

#.include <bsd.port.mk>
