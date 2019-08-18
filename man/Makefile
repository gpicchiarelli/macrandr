.include<../mkinfo.mk>

realinstall:
	cp ${DAEMON_NAME}.8 ${MANDIR}${DAEMON_NAME}.8
	makewhatis ${MANDIR}

clean:
	rm ${MANDIR}${DAEMON_NAME}.8
	makewhatis ${MANDIR}

.include <bsd.man.mk>
.include <bsd.subdir.mk>
