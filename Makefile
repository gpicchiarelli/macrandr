.include<mkinfo.mk> 

SUBDIR= src man

MAN?=${DAEMON_NAME}.8

.include <bsd.subdir.mk>
