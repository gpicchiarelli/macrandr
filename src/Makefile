.include<../mkinfo.mk>

SRC= ${NAME}.c

all: clean ${NAME}
	@chmod 0555 ${NAME}
${NAME}: ${NAME}.o
	${CC} ${LDFLAGS} -o $@ ${NAME}.o
	@echo "Compiling: done"

${NAME}.o: ${NAME}.c
	@echo "Compiling..."
	${CC} -c ${CFLAGS} ${SRC}


.PHONY: release clean uninstall dist

release: clean
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
	@echo "Cleaning up..."
	@rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.* ${NAME}.o
	@echo "Cleaning up: done."

.include <bsd.prog.mk>
