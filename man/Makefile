.include<../mkinfo.mk>

realinstall:
	cp ${DAEMON_NAME}.8 ${MANDIR}/${DAEMON_NAME}.8
	makewhatis ${LOCALBASE}/usr/share/man

clean:
	rm ${MANDIR}/${DAEMON_NAME}.8
	makewhatis ${LOCALBASE}/usr/share/man

.include <bsd.man.mk>
.include <bsd.subdir.mk>
