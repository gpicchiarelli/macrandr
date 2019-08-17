.include<mkinfo.mk> 

SUBDIR = src man

PREFIX ?= ${LOCALBASE}/usr/sbin/
BINDIR ?= ${PREFIX}

MANDIR ?= ${LOCALBASE}/man8
MAN ?= ${DAEMON_NAME}.8

.include <bsd.subdir.mk>
