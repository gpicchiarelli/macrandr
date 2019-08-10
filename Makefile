.include<mkinfo.mk> 

SUBDIR = src man
.PHONY: install clean uninstall

PREFIX ?= /usr/sbin/
BINDIR ?= ${PREFIX}

MANDIR ?= ${LOCALBASE}/man
MAN = ${DAEMON_NAME}.8

.include <bsd.subdir.mk>
