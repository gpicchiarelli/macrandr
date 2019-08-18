.include<../mkinfo.mk>

realinstall:
	cp ${DAEMON_NAME}.8 ${MANDIR}${DAEMON_NAME}.8
	makewhatis ${LOCALBASE}${MANDIR}

clean:
	rm ${MANDIR}${DAEMON_NAME}.8
	makewhatis ${LOCALBASE}${MANDIR}

.include <bsd.man.mk>
.include <bsd.subdir.mk>
