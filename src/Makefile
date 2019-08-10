.include<../mkinfo.mk>

all: ${NAME}
	@chmod 0555 ${NAME}
${NAME}: ${NAME}.o
	${CC} ${LDFLAGS} -o $@ ${NAME}.o

${NAME}.o: ${NAME}.c ${NAME}.h
	${CC} -c ${CFLAGS} \
		${NAME}.c

.PHONY: release clean uninstall dist
release:
	cp ${DAEMON_NAME} /etc/rc.d/${DAEMON_NAME}
	cp ${NAME} /usr/sbin/${NAME}
	chmod 0555 /etc/rc.d/${DAEMON_NAME}
	chmod 0555 /usr/sbin/${NAME}
	echo "${NAME}d_flags=YES\n" >> ${LOCAL_DAEMON_FILE}
	#cp ../man/${DAEMON_NAME}.8 /usr/share/man/man8/${DAEMON_NAME}.8
	rcctl enable ${DAEMON_NAME}
	rcctl start ${DAEMON_NAME}
	
dist: clean
	tar -czNs "|\(.*\)|${DAEMON_NAME}-${V}/\1|" -f ../${DAEMON_NAME}-${V}.tar.gz *
	
uninstall:
	rcctl stop ${DAEMON_NAME}
	rcctl disable ${DAEMON_NAME}
	rm /etc/rc.d/${DAEMON_NAME}
	rm /usr/sbin/${NAME}
	sed -i '/^${NAME}/d' ${LOCAL_DAEMON_FILE}
	#rm /usr/share/man/man8/${DAEMON_NAME}.8

clean:
	rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.*
	
.include <bsd.prog.mk>
