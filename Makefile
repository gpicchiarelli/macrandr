SUBDIR = src man
.PHONY: install clean uninstall

NAME= macrandr

DAEMON_NAME=${NAME}d
MAINTAINER=	Giacomo Picchiarelli <gpicchiarelli@gmail.com>
COMMENT= A daemon to change periodically MAC addresses

V= 0.1.0

PKGNAME= ${DAEMON_NAME}-${V}
DISTNAME= ${DAEMON_NAME}.${V}

PREFIX ?= /usr/sbin/
BINDIR ?= ${PREFIX}
MAN = ${DAEMON_NAME}.8

.include <bsd.subdir.mk>
