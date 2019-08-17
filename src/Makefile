.include<../mkinfo.mk>

SRC= ${NAME}.c

all: ${NAME}
	@chmod 0555 ${NAME}
${NAME}: ${NAME}.o
	${CC} ${LDFLAGS} -o $@ ${NAME}.o
	@echo "Compiling: done"

${NAME}.o: ${NAME}.c
	@echo "Compiling..."
	${CC} -c ${CFLAGS} ${SRC}

.PHONY: clean 

realinstall: all
	cp ${DAEMON_NAME} ${LOCALBASE}/etc/rc.d/${DAEMON_NAME}
	cp ${NAME} ${BINDIR}${NAME}
	chmod 0555 ${LOCALBASE}/etc/rc.d/${DAEMON_NAME}
	chmod 0555 ${BINDIR}${NAME}
	rcctl enable ${DAEMON_NAME}
	rcctl start ${DAEMON_NAME}

clean:
	@echo "Cleaning up..."
	@rm -f ${NAME} *.o ${DAEMON_NAME}-*.tar.gz tags.* src/${NAME}.o
	@echo "Cleaning up: done."
	rcctl stop ${DAEMON_NAME}
	rcctl disable ${DAEMON_NAME}
	rm ${LOCALBASE}/etc/rc.d/${DAEMON_NAME}
	rm ${BINDIR}${NAME}

.include <bsd.prog.mk>
